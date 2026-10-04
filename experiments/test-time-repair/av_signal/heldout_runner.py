"""CWEval grading process, executed inside a benchmark environment container."""

import json
import os
from pathlib import Path

from cweval.commons import compile_src
from cweval.run_tests import run_tests

case = Path(os.environ["AV_CASE_DIR"])
test_path = case / os.environ["AV_TEST_FILE"]
task_path = case / os.environ["AV_TASK_FILE"]
record = {"functional": False, "security": False}
if task_path.suffix in {".c", ".cpp", ".go"}:
    compiled = task_path.parent / "compiled" / task_path.stem
    code, stdout, stderr = compile_src(str(task_path), str(compiled), check=False)
    record["compile"] = {"returncode": code, "stdout": stdout[-1000:], "stderr": stderr[-1000:]}
    if code != 0:
        print("AV_HELDOUT:" + json.dumps(record))
        raise SystemExit(0)
results = run_tests(str(test_path))
for result in results:
    if Path(result.file).name == test_path.name:
        record["functional"] = result.functional is True
        record["security"] = result.secure is True
        break
print("AV_HELDOUT:" + json.dumps(record))
