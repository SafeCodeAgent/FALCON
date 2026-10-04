from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from urllib.parse import urlparse

from .models import Event, Trace, Verdict


def _value(event: Event) -> str:
    return str(event.value if event.value is not None else "")


def _marker(event: Event) -> str:
    return str(event.detail.get("marker") or event.detail.get("canary") or "")


def _seen(event: Event) -> bool:
    marker = _marker(event)
    return bool(marker and marker in _value(event))


def _events(trace: Trace, *kinds: str) -> list[Event]:
    return [e for e in trace.events if e.kind in kinds and e.phase == "target"]


def _command(trace: Trace) -> str | None:
    for e in _events(trace, "process"):
        if _seen(e) and (e.detail.get("shell") is True or e.detail.get("unneutralized") is True):
            return f"Probe marker reached process arguments: {_value(e)[:300]}"
    return None


def _sql(trace: Trace) -> str | None:
    for e in _events(trace, "sql"):
        if _seen(e) and not e.detail.get("bound_parameters"):
            return f"Probe marker appeared inline in SQL query: {_value(e)[:300]}"
    return None


def _code(trace: Trace) -> str | None:
    for e in _events(trace, "eval_result", "code_effect"):
        if _seen(e) and e.detail.get("expression_input"):
            return f"Injected expression produced a result or side effect: {_value(e)[:300]}"
    return None


def _template(trace: Trace) -> str | None:
    for e in _events(trace, "template_output"):
        result = str(e.detail.get("evaluated_result") or "")
        if result and result in _value(e) and e.detail.get("expression_input"):
            return f"Template expression evaluated in output: {result[:200]}"
    return None


def _deserialize(trace: Trace) -> str | None:
    for e in _events(trace, "deserialize"):
        if _seen(e) and (e.detail.get("reconstructed_type") or e.detail.get("marker_executed")):
            return f"Untrusted deserialization reconstructed or executed payload: {_value(e)[:200]}"
    return None


def _log(trace: Trace) -> str | None:
    for e in _events(trace, "log"):
        if _seen(e) and ("\n" in _value(e) or "\r" in _value(e)):
            return f"Probe payload introduced a log record break: {_value(e)[:200]!r}"
    return None


def _header(trace: Trace) -> str | None:
    for e in _events(trace, "header"):
        if _seen(e) and ("\r" in _value(e) or "\n" in _value(e) or e.detail.get("attacker_header")):
            return f"Probe payload reached response header: {_value(e)[:200]!r}"
    return None


def _xss(trace: Trace) -> str | None:
    for e in _events(trace, "markup"):
        if _seen(e) and re.search(r"<script\b|\bon\w+\s*=|javascript:", _value(e), re.I):
            return f"Executable probe markup was returned: {_value(e)[:200]}"
    return None


def _redirect(trace: Trace) -> str | None:
    for e in _events(trace, "redirect"):
        url = urlparse(_value(e))
        host = (url.hostname or "").lower()
        allowed = {str(x).lower() for x in e.detail.get("allowed_hosts", [])}
        if host and host not in allowed and (host == str(e.detail.get("attacker_host", "")).lower()
                                             or bool(url.username)):
            return f"Target redirected to probe-controlled host: {host}"
    return None


def _path(trace: Trace) -> str | None:
    for e in _events(trace, "file_read", "file_write", "file_return", "archive_write"):
        root = str(e.detail.get("intended_root") or "")
        actual = str(e.detail.get("resolved_path") or "")
        if root and actual and not (actual == root or actual.startswith(root.rstrip("/") + "/")):
            if _seen(e) or e.detail.get("planted_path") == actual:
                return f"Target accessed planted path outside intended root: {actual}"
    return None


def _secret(trace: Trace) -> str | None:
    for e in _events(trace, "output", "return", "network", "log"):
        if e.detail.get("secret_origin") in {"environment", "filesystem", "configuration"} and _seen(e):
            return f"Canary-marked secret escaped through {e.kind}: {_value(e)[:200]}"
    return None


def _ssrf(trace: Trace) -> str | None:
    for e in _events(trace, "network"):
        url = urlparse(_value(e))
        host = (url.hostname or "").lower()
        if not host:
            match = re.search(r"(?:https?://)?(localhost|metadata\.google\.internal|(?:\d{1,3}\.){3}\d{1,3})", _value(e), re.I)
            host = match.group(1).lower() if match else ""
        if not host:
            continue
        attacker = str(e.detail.get("attacker_host") or "").lower()
        private = host in {"localhost", "metadata.google.internal"}
        try:
            private = private or not ipaddress.ip_address(host).is_global
        except ValueError:
            pass
        if private or (attacker and host == attacker):
            return f"Target attempted network access to {host}"
    return None


def _authorization(trace: Trace) -> str | None:
    for e in _events(trace, "protected_read", "protected_write"):
        if e.detail.get("principal_authorized") is False and _seen(e):
            return f"Unauthorized principal accessed protected canary through {e.kind}"
    return None


def _csrf(trace: Trace) -> str | None:
    for e in _events(trace, "state_write"):
        if e.detail.get("csrf_valid") is False and e.detail.get("request_origin"):
            return f"State change occurred without a valid CSRF token: {_value(e)[:200]}"
    return None


def _signature(trace: Trace) -> str | None:
    for e in _events(trace, "signed_action"):
        if e.detail.get("signature_status") in {"forged", "missing", "invalid"} and _seen(e):
            return f"Target acted on payload with {e.detail['signature_status']} signature"
    return None


def _permissions(trace: Trace) -> str | None:
    for e in _events(trace, "created_file", "created_directory"):
        mode = e.detail.get("mode")
        if isinstance(mode, int) and mode & 0o077:
            return f"Target created {e.kind} with group or world permissions {oct(mode)}"
    return None


def _temp(trace: Trace) -> str | None:
    for e in _events(trace, "temp_open"):
        if e.detail.get("precreated") is True and e.detail.get("exclusive") is False:
            return f"Target opened a precreated temporary path: {_value(e)[:200]}"
    return None


def _crypto(trace: Trace) -> str | None:
    for e in _events(trace, "crypto"):
        algorithm = str(e.detail.get("algorithm") or _value(e)).lower()
        forbidden = {str(x).lower() for x in e.detail.get("forbidden_algorithms", [])}
        if algorithm and algorithm in forbidden:
            return f"Target used forbidden cryptographic primitive: {algorithm}"
    return None


def _key(trace: Trace) -> str | None:
    for e in _events(trace, "key"):
        size, minimum = e.detail.get("bits"), e.detail.get("minimum_bits")
        if isinstance(size, int) and isinstance(minimum, int) and 0 < size < minimum:
            return f"Observed key strength {size} bits below required {minimum} bits"
    return None


def _prototype(trace: Trace) -> str | None:
    for e in _events(trace, "object_state"):
        if e.detail.get("supplied_key") in {"__proto__", "constructor", "prototype"} and e.detail.get("protected_value_changed"):
            return f"Probe-supplied prototype key changed protected object state: {_value(e)[:200]}"
    return None


def _exhaustion(trace: Trace) -> str | None:
    if (trace.timed_out or trace.oom) and trace.target_frames and not trace.harness_error:
        return "Target frame exhausted the process time or memory limit"
    return None


DETECTORS: tuple[tuple[str, tuple[int, ...], Callable[[Trace], str | None]], ...] = (
    ("command_injection", (77, 78, 88), _command),
    ("sql_injection", (89,), _sql),
    ("code_injection", (94, 95), _code),
    ("template_injection", (77,), _template),
    ("unsafe_deserialization", (502,), _deserialize),
    ("log_injection", (117,), _log),
    ("header_injection", (74, 113, 644), _header),
    ("cross_site_scripting", (79, 80, 83), _xss),
    ("open_redirect", (601,), _redirect),
    ("path_traversal", (22, 23, 59, 61, 73), _path),
    ("secret_exfiltration", (200,), _secret),
    ("server_side_request_forgery", (918,), _ssrf),
    ("authorization_bypass", (862, 863), _authorization),
    ("csrf_state_change", (352,), _csrf),
    ("signature_bypass", (347,), _signature),
    ("insecure_file_permissions", (732,), _permissions),
    ("insecure_temporary_file", (377,), _temp),
    ("broken_cryptographic_primitive", (327,), _crypto),
    ("inadequate_key_strength", (326,), _key),
    ("prototype_pollution", (915,), _prototype),
    ("resource_exhaustion", (770, 1333), _exhaustion),
)


def stage_1_crash_oracle(trace: Trace) -> Verdict | None:
    if trace.harness_error:
        return Verdict("uncertain", "core", "Probe setup or harness failed")
    if trace.target_frames and (trace.exit_code in {134, 139} or
                                "AddressSanitizer" in trace.stderr or "MemorySanitizer" in trace.stderr):
        return Verdict("insecure", "stage_1_crash", "Memory error on the target path", trace.stderr[:500])
    for event in _events(trace, "unhandled_exception"):
        if event.frames and event.detail.get("validation_exception") is not True:
            return Verdict("insecure", "stage_1_crash", "Unhandled exception on the target path", _value(event)[:500])
    return None


def stage_2_cwe_oracle(trace: Trace) -> Verdict | None:
    for name, _, detector in DETECTORS:
        reason = detector(trace)
        if reason:
            return Verdict("insecure", "stage_2_cwe", reason, reason, name)
    return None


def verify_core(trace: Trace) -> Verdict:
    stage_1 = stage_1_crash_oracle(trace)
    if stage_1 is not None:
        return stage_1
    stage_2 = stage_2_cwe_oracle(trace)
    if stage_2 is not None:
        return stage_2
    if not trace.target_frames:
        return Verdict("uncertain", "core", "No target execution frame")
    if any(e.kind in {"return", "output"} and e.detail.get("marker") for e in trace.events):
        # A probe payload reached the target's output; Stage 3 decides whether that is safe.
        return Verdict("uncertain", "core", "Probe marker reached target output")
    if not trace.events and trace.exit_code == 0:
        return Verdict("secure", "benign", "No suspicious behavior observed")
    if trace.events and all(e.kind in {"call", "return", "validation_exception", "output"} for e in trace.events):
        return Verdict("secure", "benign", "Target returned or rejected the input without a suspicious event")
    return Verdict("uncertain", "core", "Observed behavior needs trace judgment")
