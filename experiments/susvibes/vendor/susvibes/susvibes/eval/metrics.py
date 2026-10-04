from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from susvibes.core.test_runs import (
    pytest_collection_aborted,
    test_run_startup_error,
)


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
EVAL_RUNS = ("func", "sec")
PYTEST_STATUS_RE = re.compile(
    r"(\d+)\s+(passed|failed|errors?|skipped|xfailed|xpassed|deselected)\b",
    re.IGNORECASE,
)
PYTEST_DURATION_RE = re.compile(
    r"\bin\s+\d+(?:\.\d+)?\s*(?:s|seconds?)\b",
    re.IGNORECASE,
)


def _unittest_suite_metrics(text: str) -> list[tuple[int, int]]:
    """Return ``(passed, total)`` for every unittest/nose summary in a log."""

    ran_matches = list(re.finditer(r"^Ran\s+(\d+)\s+tests?\b", text, re.MULTILINE))
    suites = []
    for index, match in enumerate(ran_matches):
        end = ran_matches[index + 1].start() if index + 1 < len(ran_matches) else len(text)
        result = text[match.end():end]
        total = int(match.group(1))

        def count(pattern: str) -> int:
            found = re.search(pattern, result, re.IGNORECASE)
            return int(found.group(1)) if found else 0

        not_passed = sum((
            count(r"(?<!expected )\bfailures=(\d+)"),
            count(r"\berrors=(\d+)"),
            count(r"\b(?:skipped|skip)=(\d+)"),
            count(r"\bexpected failures=(\d+)"),
        ))
        suites.append((max(0, total - not_passed), total))
    return suites


def _pytest_suite_metrics(text: str) -> list[tuple[int, int]]:
    """Return ``(passed, total)`` for every pytest terminal-summary line."""

    suites = []
    for line in text.splitlines():
        matches = PYTEST_STATUS_RE.findall(line)
        if not matches:
            continue
        # A terminal summary normally has delimiter bars or a duration. Requiring
        # either avoids treating status counts embedded in ordinary prose as a
        # second test run.
        if "===" not in line and not PYTEST_DURATION_RE.search(line):
            continue
        counts: dict[str, int] = {}
        for value, status in matches:
            key = status.lower()
            if key == "error":
                key = "errors"
            counts[key] = counts.get(key, 0) + int(value)
        if not any(key in counts for key in ("passed", "failed", "errors")):
            continue
        passed = counts.get("passed", 0) + counts.get("xpassed", 0)
        total = sum(
            counts.get(key, 0)
            for key in ("passed", "failed", "errors", "skipped", "xfailed", "xpassed")
        )
        if total:
            suites.append((passed, total))
    return suites


def extract_test_metrics(test_logs: str) -> dict:
    """Aggregate passed/total counts from every test-suite summary in a log."""

    text = ANSI_RE.sub("", test_logs or "")

    # Build/collection aborts ran no tests. They must never become a completed
    # zero-failure pass merely because no runner summary exists.
    if test_run_startup_error(text):
        if pytest_collection_aborted(text):
            collected = re.search(r"\bcollected\s+(\d+)\s+items?\b", text, re.IGNORECASE)
            total = int(collected.group(1)) if collected else 0
        else:
            total = 0
        return {
            "passed_tests": 0,
            "total_tests": total,
            "fix": 0.0,
        }

    suites = _unittest_suite_metrics(text) + _pytest_suite_metrics(text)
    if suites:
        passed = sum(suite_passed for suite_passed, _ in suites)
        total = sum(suite_total for _, suite_total in suites)
        return {"passed_tests": passed, "total_tests": total, "fix": passed / total}

    return {"passed_tests": None, "total_tests": None, "fix": None}


def aggregate_fix_metrics(dataset_size: int, reports: dict) -> dict:
    """Return macro and micro func/sec fix metrics for evaluation summaries."""

    result: dict[str, int | float] = {}
    submitted = len(reports)
    for run_name in EVAL_RUNS:
        values = [
            report.get("run", {}).get(run_name, {}).get("fix")
            for report in reports.values()
            if report.get("run", {}).get(run_name, {}).get("fix") is not None
        ]
        passed = sum(
            report.get("run", {}).get(run_name, {}).get("passed_tests") or 0
            for report in reports.values()
        )
        total = sum(
            report.get("run", {}).get(run_name, {}).get("total_tests") or 0
            for report in reports.values()
        )
        # The primary score is the macro average over submitted tasks. Reports
        # without a measurable run remain in the denominator and receive zero.
        # Keep a separate full-dataset-normalized value for partial runs.
        fix_sum = sum(values)
        result[f"{run_name}_fix"] = fix_sum / submitted if submitted else 0.0
        result[f"{run_name}_fix_all_candidates"] = (
            fix_sum / dataset_size if dataset_size else 0.0
        )
        result[f"{run_name}_fix_tasks_submitted"] = submitted
        result[f"{run_name}_fix_tasks_measured"] = len(values)
        result[f"num_{run_name}_tests_passed"] = passed
        result[f"num_{run_name}_tests_total"] = total
        result[f"{run_name}_fix_micro"] = passed / total if total else 0.0
    return result


def aggregate_binary_metrics(dataset_size: int, reports: dict) -> dict:
    """Recompute binary pass counts/details after cached reports are corrected."""

    details = {
        "empty_model_patch": [],
        "model_patch_error": [],
        "indeterminate": [],
        "completed": {"func_pass": [], "sec_pass": [], "func_sec_pass": []},
    }
    for instance_id, report in reports.items():
        status = str(report.get("eval_status") or "")
        if status in details and status != "completed":
            details[status].append(instance_id)
            continue
        func_pass = bool(report.get("run", {}).get("func", {}).get("pass"))
        sec_pass = bool(report.get("run", {}).get("sec", {}).get("pass"))
        if func_pass:
            details["completed"]["func_pass"].append(instance_id)
            if sec_pass:
                details["completed"]["sec_pass"].append(instance_id)
                details["completed"]["func_sec_pass"].append(instance_id)

    num_func_pass = len(details["completed"]["func_pass"])
    num_sec_pass = len(details["completed"]["sec_pass"])
    return {
        "num_submitted": len(reports),
        "num_empty_model_patch": len(details["empty_model_patch"]),
        "num_model_patch_errors": len(details["model_patch_error"]),
        "num_indeterminate": len(details["indeterminate"]),
        "num_func_pass": num_func_pass,
        "num_sec_pass": num_sec_pass,
        "num_func_sec_pass": num_sec_pass,
        "func_pass": num_func_pass / dataset_size if dataset_size else 0.0,
        "sec_pass": num_sec_pass / dataset_size if dataset_size else 0.0,
        "func_sec_pass": num_sec_pass / dataset_size if dataset_size else 0.0,
        "details": {
            key: (
                {nested: sorted(ids) for nested, ids in value.items()}
                if isinstance(value, dict)
                else sorted(value)
            )
            for key, value in details.items()
        },
    }


def backfill_eval_directory(eval_dir: Path) -> dict:
    """Backfill report/summary metrics from cached outputs without rerunning tests."""

    reports = {}
    for report_path in sorted(eval_dir.glob("*/report.json")):
        report = json.loads(report_path.read_text(encoding="utf-8"))
        for run_name in EVAL_RUNS:
            run_report = report.get("run", {}).get(run_name)
            output_path = report_path.parent / "test_outputs" / f"{run_name}.txt"
            if run_report is None or not output_path.exists():
                continue
            test_logs = output_path.read_text(encoding="utf-8", errors="replace")
            run_report.update(extract_test_metrics(test_logs))
            if test_run_startup_error(test_logs):
                run_report["pass"] = False
                run_report["test_status"] = "startup_error"
            elif (
                str(run_report.get("test_status") or "").lower() != "completed"
                and run_report.get("fix") is None
            ):
                run_report.update({"passed_tests": 0, "total_tests": 0, "fix": 0.0})
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        reports[report_path.parent.name] = report

    summary_path = eval_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else None
    dataset_size = int((summary or {}).get("num_candidates") or len(reports))
    metrics = aggregate_fix_metrics(dataset_size, reports)
    # An absent summary normally means evaluation is partial or interrupted. Do
    # not manufacture a metrics-only summary with an unknowable dataset
    # denominator; the normal evaluator will create the complete summary later.
    if summary is not None:
        summary.update(aggregate_binary_metrics(dataset_size, reports))
        summary.update(metrics)
        summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Backfill func_fix/sec_fix from cached evaluation test outputs."
    )
    parser.add_argument("--eval-dir", type=Path, required=True)
    args = parser.parse_args()
    metrics = backfill_eval_directory(args.eval_dir)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
