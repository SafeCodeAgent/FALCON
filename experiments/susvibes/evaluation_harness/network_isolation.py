"""Network isolation for coding agents that call their model inside Docker.

The task container is moved onto an internal Docker network after harness setup.
It can reach a host-side relay whose destination is fixed when the relay starts,
but it has no default route to the Internet.  This lets a CLI call its model API
without giving shell tools a general-purpose outbound connection.
"""

from __future__ import annotations

import http.server
import ipaddress
import json
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Iterable


COMPARISON_API_MODE = "responses"
COMPARISON_REASONING_EFFORT = "medium"
COMPARISON_MAX_OUTPUT_TOKENS = 32_000
COMPARISON_PROFILE = "responses_reasoning-medium_max-output-32000_no-egress_v1"

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        del req, fp, code, msg, headers, newurl
        return None


class _RelayServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        target_base_url: str,
        allowed_paths: tuple[str, ...],
    ) -> None:
        self.target_base_url = target_base_url.rstrip("/")
        self.allowed_paths = allowed_paths
        self.opener = urllib.request.build_opener(_NoRedirect())
        super().__init__(server_address, _RelayHandler)


class _RelayHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def do_GET(self) -> None:  # noqa: N802
        self._forward()

    def do_POST(self) -> None:  # noqa: N802
        self._forward()

    def do_HEAD(self) -> None:  # noqa: N802
        self._forward()

    def _write_to_client(self, data: bytes, *, flush: bool = False) -> bool:
        """Write relay output, treating a closed client as normal cancellation."""

        try:
            self.wfile.write(data)
            if flush:
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            # Claude Code can cancel an in-flight SSE response after it has the
            # event it needs or when its task process exits. The upstream body
            # is closed by _forward's finally block; do not let socketserver
            # print a misleading request-handler traceback.
            self.close_connection = True
            return False
        return True

    def _reject(self, status: int, message: str) -> None:
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self._write_to_client(body)
        self.close_connection = True

    def _forward(self) -> None:
        server = self.server
        assert isinstance(server, _RelayServer)
        parsed = urllib.parse.urlsplit(self.path)
        decoded_path = urllib.parse.unquote(parsed.path)
        if parsed.scheme or parsed.netloc or ".." in decoded_path.split("/"):
            self._reject(400, "invalid model API path")
            return
        if not any(
            parsed.path == prefix or parsed.path.startswith(f"{prefix}/")
            for prefix in server.allowed_paths
        ):
            self._reject(403, "the isolated relay only permits model API requests")
            return

        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()
        if transfer_encoding and transfer_encoding != "identity":
            self._reject(411, "chunked request bodies are not supported")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reject(400, "invalid Content-Length")
            return
        body = self.rfile.read(length) if length else None
        suffix = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        upstream_url = f"{server.target_base_url}{suffix}"
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in _HOP_BY_HOP_HEADERS | {"host", "content-length"}
        }
        request = urllib.request.Request(
            upstream_url,
            data=body,
            headers=headers,
            method=self.command,
        )
        try:
            response = server.opener.open(request, timeout=3_600)
        except urllib.error.HTTPError as exc:
            response = exc
        except Exception as exc:  # pragma: no cover - depends on external socket failures
            self._reject(502, f"model API relay failed: {exc}")
            return

        try:
            try:
                self.send_response(response.status)
                for key, value in response.headers.items():
                    if key.lower() not in _HOP_BY_HOP_HEADERS:
                        self.send_header(key, value)
                self.send_header("Connection", "close")
                self.end_headers()
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                return
            if self.command != "HEAD":
                read = getattr(response, "read1", response.read)
                while True:
                    chunk = read(64 * 1024)
                    if not chunk or not self._write_to_client(chunk, flush=True):
                        break
        finally:
            response.close()
            self.close_connection = True


class FixedUpstreamRelay:
    """HTTP relay that can forward only to one preconfigured API base URL."""

    def __init__(self, target_base_url: str, allowed_paths: Iterable[str]) -> None:
        parsed = urllib.parse.urlsplit(target_base_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Invalid model API base URL: {target_base_url!r}")
        normalized = tuple(
            path.rstrip("/") or "/"
            for path in allowed_paths
            if path.startswith("/")
        )
        if not normalized:
            raise ValueError("At least one absolute model API path is required")
        self.target_base_url = target_base_url.strip().rstrip("/")
        self.allowed_paths = normalized
        self._server: _RelayServer | None = None
        self._thread: threading.Thread | None = None

    def start(self, bind_host: str = "127.0.0.1") -> str:
        if self._server is not None:
            host, port = self._server.server_address[:2]
            return f"http://{host}:{port}"
        self._server = _RelayServer(
            (bind_host, 0),
            self.target_base_url,
            self.allowed_paths,
        )
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="av-model-relay",
            daemon=True,
        )
        self._thread.start()
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def close(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None


@dataclass
class PublishedPortNoEgressNetwork:
    """Docker bridge with reachable published ports but no outbound NAT.

    ``--network=none`` cannot be used for SWE-ReX containers because SWE-agent
    reaches their HTTP runtime through Docker's published port.  Docker's
    ``--internal`` networks also suppress that localhost publication.  A
    dedicated bridge with IP masquerading disabled preserves the host-to-runtime
    path while preventing new container-to-Internet connections.
    """

    label: str
    network_name: str | None = None

    def create(self) -> str:
        if self.network_name is not None:
            return self.network_name
        safe_label = "".join(char if char.isalnum() else "-" for char in self.label)[:24]
        network_name = f"av-{safe_label}-{uuid.uuid4().hex[:10]}"
        subprocess.run(
            [
                "docker",
                "network",
                "create",
                "--driver",
                "bridge",
                "--opt",
                "com.docker.network.bridge.enable_ip_masquerade=false",
                "--label",
                "av.network=published-port-no-egress",
                network_name,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.network_name = network_name
        return network_name

    def isolate_container(self, container: str) -> None:
        """Move a running bridge container behind the no-masquerade boundary."""

        network_name = self.create()
        subprocess.run(
            ["docker", "network", "connect", network_name, container],
            capture_output=True,
            text=True,
            check=True,
        )
        disconnected = subprocess.run(
            ["docker", "network", "disconnect", "bridge", container],
            capture_output=True,
            text=True,
        )
        if disconnected.returncode != 0:
            subprocess.run(
                ["docker", "network", "disconnect", "-f", network_name, container],
                capture_output=True,
                text=True,
            )
            raise RuntimeError(
                disconnected.stderr.strip()
                or f"Could not disconnect {container} from Docker bridge"
            )

    def close(self) -> None:
        if self.network_name is None:
            return
        subprocess.run(
            ["docker", "network", "rm", self.network_name],
            capture_output=True,
            text=True,
        )
        self.network_name = None

    def __enter__(self) -> str:
        return self.create()

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        del exc_type, exc, traceback
        self.close()


@dataclass
class RestrictedModelNetwork:
    """Move one Docker container to an internal network with a fixed relay."""

    label: str
    network_name: str | None = None
    container: str | None = None
    relay: FixedUpstreamRelay | None = None
    relay_url: str | None = None

    def activate(
        self,
        container: str,
        target_base_url: str,
        *,
        allowed_paths: Iterable[str],
    ) -> str:
        if self.relay_url is not None:
            return self.relay_url
        self.container = container
        safe_label = "".join(char if char.isalnum() else "-" for char in self.label)[:24]
        self.network_name = f"av-{safe_label}-{uuid.uuid4().hex[:10]}"
        try:
            subprocess.run(
                [
                    "docker",
                    "network",
                    "create",
                    "--internal",
                    "--label",
                    "av.network=model-only",
                    self.network_name,
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            inspected = subprocess.run(
                [
                    "docker",
                    "network",
                    "inspect",
                    "--format",
                    "{{(index .IPAM.Config 0).Gateway}}",
                    self.network_name,
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            gateway = inspected.stdout.strip()
            ipaddress.ip_address(gateway)
            self.relay = FixedUpstreamRelay(target_base_url, allowed_paths)
            self.relay_url = self.relay.start(gateway)
            subprocess.run(
                ["docker", "network", "connect", self.network_name, container],
                capture_output=True,
                text=True,
                check=True,
            )
            disconnected = subprocess.run(
                ["docker", "network", "disconnect", "bridge", container],
                capture_output=True,
                text=True,
            )
            if disconnected.returncode != 0:
                raise RuntimeError(
                    disconnected.stderr.strip()
                    or f"Could not disconnect {container} from Docker bridge"
                )
            return self.relay_url
        except Exception:
            self.close()
            raise

    def close_relay(self) -> None:
        if self.relay is not None:
            self.relay.close()
            self.relay = None
        self.relay_url = None

    def close(self) -> None:
        self.close_relay()
        if self.network_name is not None:
            if self.container is not None:
                subprocess.run(
                    ["docker", "network", "disconnect", "-f", self.network_name, self.container],
                    capture_output=True,
                    text=True,
                )
            subprocess.run(
                ["docker", "network", "rm", self.network_name],
                capture_output=True,
                text=True,
            )
            self.network_name = None
        self.container = None
