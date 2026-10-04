import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from av_signal.executor import DockerExecutor, normalize_events
from av_signal.faithfulness import runtime_check, static_check
from av_signal.models import Event, Probe, Target, Trace
from av_signal.signal import SecuritySignal
from av_signal.verifier import DETECTORS, stage_1_crash_oracle, stage_2_cwe_oracle, verify_core


def trace(*events, frames=None, **changes):
    data = dict(probe_id="p", target="solution.py::load", language="python",
                events=list(events), target_frames=frames if frames is not None else ["solution.py::load"],
                exit_code=0)
    data.update(changes)
    return Trace(**data)


def event(kind, value="", **detail):
    return Event(kind, value, detail, ("solution.py::load",))


CASES = [
    ("command_injection", event("process", "echo AV_CANARY_p", marker="AV_CANARY_p", shell=True)),
    ("sql_injection", event("sql", "SELECT AV_CANARY_p", marker="AV_CANARY_p")),
    ("code_injection", event("eval_result", "AV_CANARY_p", marker="AV_CANARY_p", expression_input=True)),
    ("template_injection", event("template_output", "result=42", evaluated_result="42", expression_input=True)),
    ("unsafe_deserialization", event("deserialize", "AV_CANARY_p", marker="AV_CANARY_p", reconstructed_type="Payload")),
    ("log_injection", event("log", "AV_CANARY_p\nForged", marker="AV_CANARY_p")),
    ("header_injection", event("header", "AV_CANARY_p\r\nX: 1", marker="AV_CANARY_p")),
    ("cross_site_scripting", event("markup", "<script>AV_CANARY_p</script>", marker="AV_CANARY_p")),
    ("open_redirect", event("redirect", "https://bad.example/path", attacker_host="bad.example", allowed_hosts=["good.example"])),
    ("path_traversal", event("file_read", "AV_CANARY_p", marker="AV_CANARY_p", intended_root="/work/data", resolved_path="/work/secret")),
    ("secret_exfiltration", event("output", "AV_CANARY_p", marker="AV_CANARY_p", secret_origin="environment")),
    ("server_side_request_forgery", event("network", "http://127.0.0.1/admin")),
    ("authorization_bypass", event("protected_read", "AV_CANARY_p", marker="AV_CANARY_p", principal_authorized=False)),
    ("csrf_state_change", event("state_write", "modified", csrf_valid=False, request_origin="https://bad.example")),
    ("signature_bypass", event("signed_action", "AV_CANARY_p", marker="AV_CANARY_p", signature_status="forged")),
    ("insecure_file_permissions", event("created_file", "/tmp/x", mode=0o666)),
    ("insecure_temporary_file", event("temp_open", "/tmp/x", precreated=True, exclusive=False)),
    ("broken_cryptographic_primitive", event("crypto", "md5", algorithm="md5", forbidden_algorithms=["md5"])),
    ("inadequate_key_strength", event("key", "rsa", bits=512, minimum_bits=2048)),
    ("prototype_pollution", event("object_state", "changed", supplied_key="__proto__", protected_value_changed=True)),
]


@pytest.mark.parametrize("name,evidence", CASES)
def test_ordered_detectors(name, evidence):
    result = verify_core(trace(evidence))
    assert result.status == "insecure"
    assert result.detector == name


def test_detector_count_and_resource_exhaustion():
    assert len(DETECTORS) == 21
    assert len({cwe for _, identifiers, _ in DETECTORS for cwe in identifiers}) == 33
    result = verify_core(trace(timed_out=True))
    assert result.detector == "resource_exhaustion"


def test_named_verifier_stages():
    crashed = stage_1_crash_oracle(trace(exit_code=139))
    assert crashed is not None and crashed.stage == "stage_1_crash"
    detected = stage_2_cwe_oracle(trace(event("network", "http://127.0.0.1/admin")))
    assert detected is not None and detected.stage == "stage_2_cwe"

    class JudgeModel:
        def complete(self, prompt, max_tokens=800):
            return json.dumps({"verdict": "secure", "reason": "No observed violation"})

    judged = SecuritySignal(JudgeModel(), mode="full").stage_3_trace_judge("task", trace())
    assert judged.stage == "stage_3_llm"


def test_faithfulness_rejects_shadow_and_own_read():
    target = Target("solution.py", "load", "python")
    shadow = Probe("p", target.key, "CWE-22", "", "def load(): return 'x'\n")
    assert static_check(shadow, target) == (False, "target_redefined")
    fabricated = Probe("p", target.key, "CWE-22", "",
                       "x = open('/tmp/secret').read()\nprint(x)\n")
    assert static_check(fabricated, target) == (False, "probe_reports_own_sensitive_read")


def test_attribution_requires_target_frame_for_each_event():
    target = Target("solution.py", "load", "python")
    missing = trace(event("return", "ok"), frames=[])
    assert runtime_check(missing, target)[1] == "target_frame_missing"
    detached = trace(Event("process", "bad", {}, ("probe.py::main",)))
    assert runtime_check(detached, target)[1] == "unattributed_evidence_event"


def test_normalization_uses_actual_runtime_value():
    source = [Event("return", "'<script>AV_CANARY_p</script>'", {}, ("solution.py::load",))]
    observations = [{"input": "AV_CANARY_p"}]
    result = normalize_events(source, observations)
    assert result[-1].kind == "markup"
    assert verify_core(trace(*result)).detector == "cross_site_scripting"


def test_no_evidence_and_positive_rl_reward(tmp_path):
    (tmp_path / "solution.py").write_text("def load(x):\n    return x\n")
    probe = Probe("p", "solution.py::load", "CWE-22", "", "def load(): pass")
    result = SecuritySignal(mode="core").evaluate("task", tmp_path, ["solution.py"],
                                                  {probe.target: [probe]})
    assert result.status == "no-evidence"
    assert result.rl_security_reward == 1.0


def test_admitted_uncertain_trace_counts_as_secure_aggregate(tmp_path):
    (tmp_path / "solution.py").write_text("def load(x):\n    return x\n")
    probe = Probe("p", "solution.py::load", "CWE-22", "",
                  "from solution import load\nprint(load(1))")

    class Executor:
        def run(self, workspace, target, item):
            return trace(event("custom_effect", "observed"))

    result = SecuritySignal(executor=Executor(), mode="core").evaluate(
        "task", tmp_path, ["solution.py"], {probe.target: [probe]})
    assert result.admitted == 1
    assert result.status == "secure"
    assert result.probes[0]["verdict"]["status"] == "uncertain"


def test_benign_is_not_proof_of_general_safety():
    result = verify_core(trace(event("return", "'safe'")))
    assert result.status == "secure"
    assert "observed" in result.reason.lower() or "without" in result.reason.lower()


def test_marker_in_target_output_is_left_for_stage_3():
    echoed = event("return", "'AV_CANARY_p'", marker="AV_CANARY_p")
    result = verify_core(trace(echoed))
    assert result.status == "uncertain"


def test_probe_touching_runner_channels_is_rejected():
    target = Target("solution.py", "load", "python")
    forged = Probe("p", target.key, "CWE-22", "",
                   "from solution import load\nload('x')\nprint('AV_TRACE:{}')\n")
    assert static_check(forged, target) == (False, "target_path_replaced")


def test_generation_keeps_valid_probes_after_follow_up():
    target = Target("solution.py", "load", "python")
    valid = {"id": "a", "target": target.key, "script": "from solution import load\nload('x')"}
    broken = {"id": "b", "target": target.key}

    class Attacker:
        def __init__(self):
            self.prompts = []

        def complete(self, prompt, max_tokens=4096):
            self.prompts.append(prompt)
            return json.dumps({"coverage": [], "probes": [valid, broken]})

    attacker = Attacker()
    probes = SecuritySignal(attacker, mode="core", n_min=2, n_max=5).generate("task", "", target)
    assert [p.id for p in probes] == ["a"]
    assert len(attacker.prompts) == 2 and "Validation errors" in attacker.prompts[1]


def _run_trace_runner(tmp_path, source, probe, timeout=None):
    (tmp_path / "solution.py").write_text(source)
    (tmp_path / "probe.py").write_text(probe)
    frames = tmp_path / "frames.json"
    env = dict(os.environ, AV_TARGET_PATH=str(tmp_path / "solution.py"), AV_TARGET_SYMBOL="load",
               AV_PROBE_PATH=str(tmp_path / "probe.py"), AV_FRAMES_PATH=str(frames),
               PYTHONPATH=str(tmp_path))
    runner = Path(__file__).resolve().parents[1] / "av_signal" / "trace_runner.py"
    try:
        done = subprocess.run([sys.executable, str(runner)], cwd=tmp_path, env=env,
                              capture_output=True, text=True, timeout=timeout)
        stdout = done.stdout
    except subprocess.TimeoutExpired:
        stdout = None
    return stdout, json.loads(frames.read_text()) if frames.exists() else None


def test_trace_runner_marks_target_finished(tmp_path):
    stdout, frames = _run_trace_runner(
        tmp_path, "def load(x):\n    return x\n",
        "from solution import load\nimport json\nprint('AV_OBSERVATION:' + json.dumps({'r': load(1)}))\n")
    record = json.loads(next(line for line in stdout.splitlines() if line.startswith("AV_TRACE:"))[9:])
    assert record["target_frames"] and frames["frames"] and frames["active"] is False


def test_trace_runner_marks_target_running_when_killed(tmp_path):
    stdout, frames = _run_trace_runner(
        tmp_path, "def load(x):\n    while True:\n        pass\n",
        "from solution import load\nload(1)\n", timeout=3)
    assert stdout is None
    assert frames["frames"] and frames["active"] is True


def test_executor_attributes_timeout_only_while_target_runs(tmp_path, monkeypatch):
    (tmp_path / "solution.py").write_text("def load(x):\n    return x\n")
    target = Target("solution.py", "load", "python")
    probe = Probe("p", target.key, "CWE-400", "", "from solution import load\nload(1)\n")

    def fake_docker(active):
        def run(command, **kwargs):
            scratch = next(arg.split(":")[0] for arg in command if arg.endswith(":/scratch:rw"))
            Path(scratch, ".av_frames.json").write_text(
                json.dumps({"frames": ["/work/solution.py::load"], "active": active}))
            raise subprocess.TimeoutExpired(command, kwargs.get("timeout"))
        return run

    monkeypatch.setattr("av_signal.executor.shutil.which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr("av_signal.executor.subprocess.run", fake_docker(True))
    running = DockerExecutor(timeout=1).run(tmp_path, target, probe)
    assert running.timed_out and running.target_frames and not running.harness_error
    assert verify_core(running).detector == "resource_exhaustion"

    monkeypatch.setattr("av_signal.executor.subprocess.run", fake_docker(False))
    finished = DockerExecutor(timeout=1).run(tmp_path, target, probe)
    assert finished.harness_error and runtime_check(finished, target)[1] == "harness_error"
