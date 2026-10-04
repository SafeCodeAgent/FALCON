import json
import os
import signal
import shutil
import subprocess
import getpass
import shlex
from pathlib import Path

from susvibes.core.constants import ContainerLimits, AGENT_RUN_LOG_DIR
from susvibes.core.utils import load_file, save_file
from evaluation_harness.network_isolation import PublishedPortNoEgressNetwork


class SWEAgentPort:
    """Drives a `sweagent run-batch` over a batch of tasks.

    Shared by curation and evaluation. The run configuration (SWE-agent config,
    model, workers, conda env, ...) is supplied by the caller — typically loaded
    from that caller's own settings via `from_settings` — not from any fixed file.
    Env-agent runs are the same port with `mount_docker_socket=True`.
    """

    def __init__(
        self,
        run_name: str,
        dir: str | Path,
        agent_env: str,
        config_name: str | list[str],
        model: dict,
        num_workers: int,
        mount_docker_socket: bool = False,
        output_dir: str | Path | None = None,
        redo_existing: bool = False,
        mode: str = "default",
        legacy_runner_path: str | Path | None = None,
        falcon_config: dict | None = None,
        network_disabled: bool = False,
        docker_network: str | None = None,
    ) -> None:
        self.run_name = run_name
        self.dir = Path(dir)
        self.agent_env = agent_env
        self.config_name = config_name
        self.model = model
        self.num_workers = num_workers
        self.mount_docker_socket = mount_docker_socket
        self.output_dir = Path(output_dir).resolve() if output_dir else None
        self.redo_existing = redo_existing
        if mode not in {"default", "legacy"}:
            raise ValueError(f"Unsupported SWE-agent mode: {mode}")
        self.mode = mode
        self.legacy_runner_path = Path(legacy_runner_path).resolve() if legacy_runner_path else None
        self.falcon_config = falcon_config or {}
        self.network_disabled = network_disabled
        self.docker_network = docker_network
        self._managed_no_egress_network: PublishedPortNoEgressNetwork | None = None
        if self.network_disabled and self.docker_network:
            raise ValueError("Choose either network_disabled or docker_network, not both.")
        if self.mode == "legacy" and self.legacy_runner_path is None:
            raise ValueError("legacy_runner_path is required for SWE-agent legacy mode.")
        self.task_instances: list[dict] = []
        self.get_instances_path().parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_settings(cls, setting: dict, run_name: str = None, **overrides) -> "SWEAgentPort":
        config = {**setting, **{k: v for k, v in overrides.items() if v is not None}}
        if run_name is not None:
            config["run_name"] = run_name
        return cls(**config)

    def get_instances_path(self) -> Path:
        return AGENT_RUN_LOG_DIR / f"{self.run_name}_instances.yaml"

    def add_task(
        self,
        repo_type: str,
        problem_statement: str,
        instance_id: str,
        repo_dir: Path = None,
        repo_name: str = None,
        image: str = None,
        base_commit: str = None,
        extra_fields: dict = None,
    ) -> None:
        assert repo_type in ["local", "preexisting"]
        repo_config = {"type": repo_type, "base_commit": base_commit or "HEAD"}
        if repo_type == "local":
            repo_config["path"] = str(repo_dir.resolve())
        elif repo_type == "preexisting":
            repo_config["repo_name"] = repo_name
        docker_args = [
            f"--memory={ContainerLimits.MEM_LIMIT}",
            f"--cpus={ContainerLimits.CPU_LIMIT}",
        ]
        if self.docker_network:
            docker_args.insert(0, f"--network={self.docker_network}")
        if self.mount_docker_socket:
            docker_args = ["-v", "/var/run/docker.sock:/var/run/docker.sock"] + docker_args
        task_instance = {
            "env": {
                "deployment": {
                    "type": "docker",
                    "image": image or "python:3.11",
                    "python_standalone_dir": "/root",
                    "docker_args": docker_args,
                },
                "repo": repo_config,
            },
            "problem_statement": {
                "type": "text",
                "text": problem_statement,
                "id": instance_id,
            },
        }
        for key, value in (extra_fields or {}).items():
            task_instance[key].update(value)
        self.task_instances.append(task_instance)

    def before_start(self) -> None:
        try:
            if self.network_disabled:
                if self._managed_no_egress_network is None:
                    self._managed_no_egress_network = PublishedPortNoEgressNetwork(
                        f"swe-{self.run_name}"
                    )
                self._managed_no_egress_network.create()
            save_file(self.task_instances, self.get_instances_path())
        except Exception:
            if self._managed_no_egress_network is not None:
                self._managed_no_egress_network.close()
                self._managed_no_egress_network = None
            raise
        print(f"SWE-agent tasks saved to {self.get_instances_path()}.")

    @staticmethod
    def after_completion(agent_output_dir: Path, submitted_only: bool = False) -> tuple[list, float | None]:
        # SWE-agent merges only the instances selected in the current invocation
        # into preds.json. Rebuild from every per-instance prediction so targeted
        # repair reruns do not hide the already completed benchmark instances.
        prediction_files = sorted(agent_output_dir.glob("*/*.pred"))
        if prediction_files:
            predictions = {}
            for prediction_file in prediction_files:
                prediction = json.loads(prediction_file.read_text(encoding="utf-8"))
                instance_id = prediction["instance_id"]
                if instance_id in predictions:
                    raise ValueError(f"Duplicate SWE-agent prediction for {instance_id}.")
                predictions[instance_id] = prediction
        else:
            predictions = load_file(agent_output_dir / "preds.json")
        exit_statuses = load_file(agent_output_dir / "run_batch_exit_statuses.yaml")
        total_cost = exit_statuses.get("total_cost", None)
        if submitted_only:
            instances_by_status = exit_statuses["instances_by_exit_status"]
            submitted_ids = instances_by_status.get("skipped (submitted)", []) + \
                instances_by_status.get("submitted", [])
            predictions = [pred for pred in predictions.values() if
                           pred["instance_id"] in submitted_ids]
        else:
            predictions = list(predictions.values())
        return predictions, total_cost

    def get_output_dir(self) -> Path:
        if self.output_dir is not None:
            return self.output_dir
        folder_name_template = "{}__{}__t-0.00__p-1.00__c-{:.2f}___{}_instances"
        return (self.dir / "trajectories" / getpass.getuser() /
            folder_name_template.format(
                self.config_name, self.model["name"],
                self.model["per_instance_cost_limit"], self.run_name
            )).resolve()

    def remove_results(self, instance_ids: list) -> None:
        num_removed = 0
        for instance_id in instance_ids:
            result_dir = self.get_output_dir() / instance_id
            if result_dir.exists():
                shutil.rmtree(result_dir)
                num_removed += 1
        print(f"Removed results for {num_removed} instances in run {self.run_name}.")

    def _config_args(self) -> str:
        names = [self.config_name] if isinstance(self.config_name, str) else self.config_name
        paths = [
            name if str(name).endswith((".yaml", ".yml")) else f"config/{name}.yaml"
            for name in names
        ]
        return " ".join(f"--config={path}" for path in paths)

    def _model_args(self) -> str:
        """Render optional GenericAPIModelConfig overrides for SWE-agent."""

        args = [f"--agent.model.name={self.model['name']}"]
        for key in (
            "api_base",
            "api_key",
            "max_input_tokens",
            "max_output_tokens",
            "completion_kwargs",
        ):
            if key not in self.model:
                continue
            value = self.model[key]
            if isinstance(value, (dict, list)) or value is None:
                serialized = json.dumps(value, separators=(",", ":"))
            elif isinstance(value, bool):
                serialized = str(value).lower()
            else:
                serialized = str(value)
            args.append(shlex.quote(f"--agent.model.{key}={serialized}"))
        return " ".join(args)

    def get_run_command(self) -> str:
        runner = "sweagent run-batch"
        if self.mode == "legacy":
            assert self.legacy_runner_path is not None
            falcon = {
                "model": "gpt-5.4-mini",
                "profile": "v9",
                "max_iterations": 5,
                "min_tests": 2,
                "max_tests": 5,
                "probe_timeout": 20.0,
                "api_timeout": 600.0,
                "attacker_mode": "agentic",
                "attacker_max_steps": 30,
                "repair_inconclusive": False,
                **self.falcon_config,
            }
            runner = (
                f"python {shlex.quote(str(self.legacy_runner_path))} "
                f"--falcon-model={shlex.quote(str(falcon['model']))} "
                f"--falcon-profile={shlex.quote(str(falcon['profile']))} "
                f"--falcon-max-iterations={int(falcon['max_iterations'])} "
                f"--falcon-min-tests={int(falcon['min_tests'])} "
                f"--falcon-max-tests={int(falcon['max_tests'])} "
                f"--falcon-probe-timeout={float(falcon['probe_timeout'])} "
                f"--falcon-api-timeout={float(falcon['api_timeout'])} "
                f"--falcon-attacker-mode={shlex.quote(str(falcon['attacker_mode']))} "
                f"--falcon-attacker-max-steps={int(falcon['attacker_max_steps'])}"
                + (
                    f" --falcon-attacker-prompt={shlex.quote(str(falcon['attacker_prompt_path']))}"
                    if falcon.get("attacker_prompt_path")
                    else ""
                )
                + (
                    f" --falcon-stage3-prompt={shlex.quote(str(falcon['stage3_prompt_path']))}"
                    if falcon.get("stage3_prompt_path")
                    else ""
                )
                + (
                    " --falcon-repair-inconclusive"
                    if falcon["repair_inconclusive"]
                    else ""
                )
            )
        cmd = (
            f"conda run -n {self.agent_env} --live-stream "
            f"{runner} "
            f"{self._config_args()} "
            f"{self._model_args()} "
            f"--agent.model.per_instance_cost_limit={self.model['per_instance_cost_limit']} "
            f"--agent.model.per_instance_call_limit={self.model['per_instance_call_limit']} "
            "--instances.type=expert_file "
            f"--instances.path={self.get_instances_path().resolve()} "
            f"--num_workers={self.num_workers} "
            f"--redo_existing={str(self.redo_existing).lower()}"
        )
        if self.output_dir is not None:
            cmd += f" --output_dir={shlex.quote(str(self.output_dir))}"
        return cmd

    def run_batch(self) -> Path:
        print(f"Running {self.run_name} with {len(self.task_instances)} tasks in {self.mode} mode...")
        cmd = self.get_run_command()
        proc = None
        try:
            process_environment = dict(os.environ)
            if self._managed_no_egress_network is not None:
                process_environment["SUSVIBES_NO_EGRESS_NETWORK"] = (
                    self._managed_no_egress_network.network_name or ""
                )
            proc = subprocess.Popen(
                cmd,
                cwd=self.dir,
                shell=True,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                env=process_environment,
            )
            proc.wait()
        except KeyboardInterrupt:
            if proc is not None:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait()
            raise
        finally:
            if self._managed_no_egress_network is not None:
                self._managed_no_egress_network.close()
                self._managed_no_egress_network = None
        assert proc is not None
        if proc.returncode != 0:
            raise subprocess.SubprocessError(
                f"Command failed with return code {proc.returncode}."
            )
        return self.get_output_dir()
