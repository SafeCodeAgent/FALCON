import argparse
import json
from pathlib import Path

from susvibes.core.constants import *
from susvibes.eval.task import TasksHandler, get_summary, print_summary
from susvibes.eval.strategies.tools import apply_safety_strategy
from susvibes.core.utils import load_file, save_file


def incomplete_prediction_reasons(predictions_path: Path, predictions: list) -> list[str]:
    """Explain why a harness checkpoint is not ready for evaluation."""

    reasons = []
    run_status_path = predictions_path.parent / "run_status.json"
    if run_status_path.exists():
        run_status = load_file(run_status_path)
        if run_status.get("status") != "complete":
            reasons.append(
                f"{run_status.get('incomplete_count', '?')} tasks are incomplete "
                f"according to {run_status_path}"
            )
    failed_ids = [
        str(item.get("instance_id") or "unknown")
        for item in predictions
        if isinstance(item, dict)
        and (
            item.get("claude_success") is False
            or item.get("opencode_success") is False
            or bool(item.get("error"))
        )
    ]
    if failed_ids:
        preview = ", ".join(failed_ids[:3])
        suffix = "..." if len(failed_ids) > 3 else ""
        reasons.append(
            f"{len(failed_ids)} prediction records contain harness failures "
            f"({preview}{suffix})"
        )
    null_patch_ids = [
        str(item.get("instance_id") or "unknown")
        for item in predictions
        if isinstance(item, dict)
        and (
            PredictionKeys.PREDICTION not in item
            or item.get(PredictionKeys.PREDICTION) is None
        )
    ]
    if null_patch_ids:
        preview = ", ".join(null_patch_ids[:3])
        suffix = "..." if len(null_patch_ids) > 3 else ""
        reasons.append(
            f"{len(null_patch_ids)} prediction records have a missing/null model patch "
            f"({preview}{suffix})"
        )
    return reasons

def prepare_dataset(run_id: str, dataset_id: str, strategy: str, feedback_tool: str = None, instance_ids: list = None):
    dataset_path = get_dataset_path('dataset', dataset_id)
    dataset = load_file(dataset_path)
    if instance_ids is not None:
        dataset = [data_record for data_record in dataset if data_record["instance_id"] in set(instance_ids)]
    for data_record in dataset:
        problem_statement = apply_safety_strategy(data_record["problem_statement"],
            strategy, data_record["cwe_ids"], dataset, feedback_tool,
            data_record.get("test_patch"))
        data_record["problem_statement"] = problem_statement
    eval_dataset_path = dataset_path.parent / \
        (dataset_path.stem + f"_{run_id}_{strategy}" + dataset_path.suffix)
    save_file(dataset, eval_dataset_path)

def run_evaluation(
    run_id: str,
    dataset_id: str,
    predictions: list,
    strategy: str,
    max_workers: int,
    force: bool = False,
    instance_ids: list = None,
    evaluate_empty_patches: bool = False,
):
    handler = TasksHandler(
        strategy,
        run_id,
        dataset_id,
        evaluate_empty_patches=evaluate_empty_patches,
    )
    handler.run_evaluation_threadpool(predictions, max_workers, force, instance_ids=instance_ids)
    for model_name_or_path, model_reports in handler.reports.items():
        eval_summary = get_summary(handler.dataset, model_reports, strategy, instance_ids=instance_ids)
        summary_path = EVAL_LOG_DIR / run_id / strategy / model_name_or_path / LOG_SUMMARY
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        save_file(eval_summary, summary_path)
        print(f"\n=== {model_name_or_path} ===")
        print_summary(eval_summary)
        print(f"Summary saved to {summary_path}.")

def main():
    """Entry point for the susvibes-eval command."""
    parser = argparse.ArgumentParser(description="Run evaluation for agent predictions.")
    parser.add_argument(
        "--run_id",
        type=str,
        default="default",
        help="Unique ID that identifies the run.",
    )
    parser.add_argument(
        "--predictions_path",
        type=Path,
        help="Path to the predictions file.",
    )
    parser.add_argument(
        "--max_workers",
        type=int,
        default=5,
        help="Number of threads to use for environment setup.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-run, ignoring any reusable evaluation report.",
    )
    parser.add_argument(
        "--instance_ids",
        type=json.loads,
        default=None,
        help="Only run for the given instance IDs.",
    )
    parser.add_argument(
        "--allow_incomplete_predictions",
        action="store_true",
        help=(
            "Evaluate a partial/failed harness checkpoint intentionally. "
            "Missing/null/empty patches run the normal tests against the "
            "unchanged checkout instead of receiving an automatic zero."
        ),
    )

    # Advanced usage
    parser.add_argument(
        "--dataset_id",
        type=str,
        default="default",
        help="[Advanced Usage] Run ID of the dataset to read (datasets/<dataset_id>/...).",
    )
    parser.add_argument(
        "--prepare_dataset",
        action="store_true",
        help="[Advanced Usage] Prepare the evaluation dataset with the strategy's problem-statement prompt (the base statement unchanged when strategy is `none`).",
    )
    parser.add_argument(
        "--strategy",
        type=str,
        default="none",
        choices=["none", "generic", "self-selection", "oracle", "feedback-driven", "sec-test"],
        help="Advanced strategy used in the evaluation."
    )
    parser.add_argument(
        "--feedback_tool",
        type=str,
        help="Name of the tool used to get feedback from security tests."
    )

    args = parser.parse_args()
    # --dataset_id picks which datasets/<dataset_id>/ dataset to read (default: "default");
    # --run_id only sets the eval-log output directory (logs/eval/<run_id>/...).
    if args.prepare_dataset:
        prepare_dataset(args.run_id, args.dataset_id, args.strategy, args.feedback_tool, instance_ids=args.instance_ids)
    else:
        predictions = load_file(args.predictions_path)
        incomplete_reasons = incomplete_prediction_reasons(
            args.predictions_path,
            predictions,
        )
        if incomplete_reasons and not args.allow_incomplete_predictions:
            parser.error(
                "Refusing to evaluate incomplete predictions: "
                + "; ".join(incomplete_reasons)
                + ". Rerun inference first. Use --allow_incomplete_predictions "
                "only if partial evaluation is intentional."
            )
        run_evaluation(args.run_id, args.dataset_id, predictions, args.strategy,
            args.max_workers, args.force, instance_ids=args.instance_ids,
            evaluate_empty_patches=args.allow_incomplete_predictions)

if __name__ == "__main__":
    main()
