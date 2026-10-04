from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train-parquet", type=Path, required=True)
    parser.add_argument("--val-parquet", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--probes", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gpus", type=int, default=8)
    parser.add_argument("--reward-workers", type=int, default=8)
    parser.add_argument("--reward", choices=("av", "real", "seccodeprm", "av+real",
                                             "av+seccodeprm", "real+seccodeprm"), default="av")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("overrides", nargs="*")
    args = parser.parse_args()
    if "av" in args.reward.split("+") and args.probes is None:
        parser.error("--probes is required for reward settings that include av")
    rl_root = Path(__file__).resolve().parent
    package_root = rl_root.parent / "test-time-repair"
    paths = [str(rl_root), str(package_root)]
    os.environ["PYTHONPATH"] = os.pathsep.join(paths + [os.environ.get("PYTHONPATH", "")])
    sys.path.insert(0, str(rl_root))
    from hydra import compose, initialize_config_dir

    if args.probes:
        os.environ["AV_PROBE_FILE"] = str(args.probes.resolve())
    os.environ["AV_REWARD"] = args.reward
    os.environ.setdefault("AV_RL_IMAGE", "av-python:latest")
    config_dir = rl_root / "verl" / "trainer" / "config"
    overrides = [
        f"data.train_files={args.train_parquet.resolve()}",
        f"data.val_files={args.val_parquet.resolve()}",
        "algorithm.adv_estimator=grpo", "data.train_batch_size=64",
        "data.max_prompt_length=375", "data.val_batch_size=64",
        "data.max_response_length=2048", f"actor_rollout_ref.model.path={args.model}",
        "actor_rollout_ref.actor.optim.lr=1e-6",
        "actor_rollout_ref.actor.ppo_mini_batch_size=32",
        "actor_rollout_ref.actor.ppo_micro_batch_size_per_gpu=2",
        "actor_rollout_ref.actor.use_kl_loss=false",
        "actor_rollout_ref.rollout.n=8",
        "actor_rollout_ref.rollout.tensor_model_parallel_size=2",
        "actor_rollout_ref.rollout.gpu_memory_utilization=0.5",
        "actor_rollout_ref.rollout.log_prob_micro_batch_size_per_gpu=2",
        "actor_rollout_ref.ref.log_prob_micro_batch_size_per_gpu=2",
        "algorithm.kl_ctrl.kl_coef=0.001", "trainer.total_epochs=50",
        f"trainer.n_gpus_per_node={args.gpus}", "trainer.nnodes=1",
        f"trainer.default_local_dir={args.output.resolve()}",
        "trainer.logger=['console']", "trainer.val_before_train=false",
        "trainer.test_freq=-1", "trainer.save_freq=100",
        "trainer.project_name=attacker-verifier", f"trainer.experiment_name={args.reward.replace('+', '_')}",
        f"+reward_model.num_processes={args.reward_workers}",
        f"+reward_model.train_reward={args.reward}",
    ] + args.overrides
    with initialize_config_dir(config_dir=str(config_dir.resolve()), version_base=None):
        config = compose(config_name="ppo_trainer", overrides=overrides)
    if args.dry_run:
        from omegaconf import OmegaConf
        print(json.dumps(OmegaConf.to_container(config, resolve=True), indent=2, default=str))
        return
    from verl.trainer.main_ppo import run_ppo
    from reward import compute_score
    run_ppo(config, compute_score=compute_score)


if __name__ == "__main__":
    main()
