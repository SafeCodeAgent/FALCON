# Copyright 2024 Bytedance Ltd. and/or its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from verl import DataProto
from verl.utils.reward_score import _default_compute_score
import torch
import multiprocessing
# import multiprocessing as mp
import time
import datetime
import signal
from tqdm import tqdm
import os
from functools import partial
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
import time

def _normalize_score(score):
    """Always return (main, ut, mypy, scpd) floats."""
    if isinstance(score, list):
        s, ut, my, sc = score
        return float(s), float(ut), float(my), float(sc)
    return float(score), 0.0, 0.0, 0.0
def handler(signum, frame):
    raise TimeoutError("Function timed out!")


class NaiveRewardManager:
    """The reward manager.
    """

    def __init__(self, tokenizer, num_examine, compute_score=None, config=None, 
                 reward_setting=None, eval_mode=False, num_processes=16) -> None:
        self.tokenizer = tokenizer
        self.num_examine = num_examine  # the number of batches of decoded responses to print to the console
        self.compute_score = compute_score or _default_compute_score
        self.config = config
        
        self.reward_setting = reward_setting
        self.eval_mode = eval_mode  # whether to use the reward selector for evaluation
        self.num_processes = num_processes  # number of processes for multiprocessing
        self.global_step = None

    def _extra_info_with_rollout_metadata(self, extra_info, batch_index, data_source):
        if not isinstance(extra_info, dict):
            return extra_info
        copied = dict(extra_info)
        copied["_rl_rollout"] = {
            "global_step": self.global_step,
            "batch_index": int(batch_index),
            "data_source": str(data_source),
            "eval_mode": bool(self.eval_mode),
            "split": "val" if self.eval_mode else "train",
        }
        return copied

    def compute_score_with_timeout(self, *args):
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(600)
        score = 0
        try:
            data_source, sequences_str, ground_truth, extra_info, *_ = args
            score = self.compute_score(
                data_source=data_source,
                solution_str=sequences_str,
                ground_truth=ground_truth,
                extra_info=extra_info,
                config=self.config,
                reward_setting=self.reward_setting,
                eval_mode=self.eval_mode,
            )
        finally:
            signal.alarm(0)
        return score

    def __call__(self, data: DataProto):
        return self.call_for_seccodeplt_fast(data)


    def call_for_seccodeplt(self, data: DataProto):
        """We will expand this function gradually based on the available datasets"""

        # If there is rm score, we directly return rm score. Otherwise, we compute via rm_score_fn
        if 'rm_scores' in data.batch.keys():
            return data.batch['rm_scores']

        reward_tensor = torch.zeros_like(data.batch['responses'], dtype=torch.float32)
        reward_tensor_ut = torch.zeros_like(data.batch['responses'], dtype=torch.float32)
        reward_tensor_mypy = torch.zeros_like(data.batch['responses'], dtype=torch.float32)
        reward_tensor_scpd = torch.zeros_like(data.batch['responses'], dtype=torch.float32)

        already_print_data_sources = {}

        for i in tqdm(range(len(data)), desc='Computing reward for batch ...'):
            data_item = data[i]  # DataProtoItem

            prompt_ids = data_item.batch['prompts']

            prompt_length = prompt_ids.shape[-1]

            valid_prompt_length = data_item.batch['attention_mask'][:prompt_length].sum()
            valid_prompt_ids = prompt_ids[-valid_prompt_length:]

            response_ids = data_item.batch['responses']
            valid_response_length = data_item.batch['attention_mask'][prompt_length:].sum()
            valid_response_ids = response_ids[:valid_response_length]

            # decode
            sequences = torch.cat((valid_prompt_ids, valid_response_ids))
            sequences_str = self.tokenizer.decode(sequences)

            ground_truth = data_item.non_tensor_batch['reward_model']['ground_truth']

            data_source = data_item.non_tensor_batch['data_source']

            extra_info = data_item.non_tensor_batch.get('extra_info', None)
            extra_info = self._extra_info_with_rollout_metadata(extra_info, i, data_source)

            st_t = time.time()
            score = self.compute_score(
                data_source=data_source,
                solution_str=sequences_str,
                ground_truth=ground_truth,
                extra_info=extra_info,
                config=self.config,
                eval_mode=self.eval_mode,
            )
            end_t = time.time()
            elapse = end_t - st_t
            print(f'[elapsed time] = {elapse}')
            if isinstance(score, list):
                score, ut_score, mypy_score, scpd_score = score  # for seccodeplt
            else:
                ut_score = 0.0
                mypy_score = 0.0
                scpd_score = 0.0

            reward_tensor[i, valid_response_length - 1] = score
            reward_tensor_ut[i, valid_response_length - 1] = ut_score
            reward_tensor_mypy[i, valid_response_length - 1] = mypy_score
            reward_tensor_scpd[i, valid_response_length - 1] = scpd_score

            if data_source not in already_print_data_sources:
                already_print_data_sources[data_source] = 0

            if already_print_data_sources[data_source] < self.num_examine:
                already_print_data_sources[data_source] += 1
                print(sequences_str)

        return reward_tensor, reward_tensor_ut, reward_tensor_mypy, reward_tensor_scpd


    def _seccodeplt_score_worker(self, args):
        data_source, sequences_str, ground_truth, extra_info, config, eval_mode = args

        # Import inside worker (safe for multiprocessing)
        # from verl.utils.reward_score.seccodeplt import compute_score

        # t0 = time.time()
        score = self.compute_score(
            data_source=data_source,
            solution_str=sequences_str,
            ground_truth=ground_truth,
            extra_info=extra_info,
            config=config,
            eval_mode=eval_mode,
        )
        return score


    def call_for_seccodeplt_fast(self, data):
        """Fast version: preprocess -> parallel scoring -> writeback"""

        # If there is rm score, we directly return rm score. Otherwise, we compute via rm_score_fn
        if "rm_scores" in data.batch.keys():
            return data.batch["rm_scores"]

        reward_tensor = torch.zeros_like(data.batch["responses"], dtype=torch.float32)
        reward_tensor_ut = torch.zeros_like(data.batch["responses"], dtype=torch.float32)
        reward_tensor_mypy = torch.zeros_like(data.batch["responses"], dtype=torch.float32)
        reward_tensor_scpd = torch.zeros_like(data.batch["responses"], dtype=torch.float32)

        already_print_data_sources = {}

        # ============================================================
        # Phase 1) Preprocess everything (decode, meta, lengths)
        # ============================================================
        packed = []
        print(f'Phase 1/3: Preprocess + decode ...')
        for i in range(len(data)):
            data_item = data[i]  # DataProtoItem

            prompt_ids = data_item.batch["prompts"]
            prompt_length = prompt_ids.shape[-1]

            valid_prompt_length = int(data_item.batch["attention_mask"][:prompt_length].sum().item())
            valid_prompt_ids = prompt_ids[-valid_prompt_length:] if valid_prompt_length > 0 else prompt_ids[:0]

            response_ids = data_item.batch["responses"]
            valid_response_length = int(data_item.batch["attention_mask"][prompt_length:].sum().item())
            valid_response_ids = response_ids[:valid_response_length] if valid_response_length > 0 else response_ids[:0]

            sequences = torch.cat((valid_prompt_ids, valid_response_ids), dim=0)
            sequences_str = self.tokenizer.decode(sequences)

            ground_truth = data_item.non_tensor_batch["reward_model"]["ground_truth"]
            data_source = data_item.non_tensor_batch["data_source"]
            extra_info = data_item.non_tensor_batch.get("extra_info", None)
            extra_info = self._extra_info_with_rollout_metadata(extra_info, i, data_source)

            packed.append(
                {
                    "i": i,
                    "valid_response_length": valid_response_length,
                    "sequences_str": sequences_str,
                    "data_source": data_source,
                    "ground_truth": ground_truth,
                    "extra_info": extra_info,
                }
            )

        # ============================================================
        # Phase 2) Parallel compute_score for all items
        # ============================================================
        max_workers = max(1, int(self.num_processes or max(1, int(os.cpu_count() / 2))))
        args_list = [
            (
                x["data_source"],
                x["sequences_str"],
                x["ground_truth"],
                x["extra_info"],
                self.config,
                self.eval_mode,
            )
            for x in packed
        ]

        # Use fork on Linux to reduce overhead (no __main__ guard needed)
        ctx = multiprocessing.get_context("fork")

        scored = []
        print(f'Phase 2/3: Scoring (parallel, workers={max_workers}) ...')
        with ProcessPoolExecutor(max_workers=max_workers, mp_context=ctx) as ex:
            for out in ex.map(self._seccodeplt_score_worker, args_list, chunksize=4):
                scored.append(out)

        # ============================================================
        # Phase 3) Write back reward tensors + printing
        # ============================================================
        print('Phase 3/3: Writeback ...')
        security_scores = []
        for x, score in zip(packed, scored):
            i = x["i"]
            valid_response_length = x["valid_response_length"]

            # print(f"[elapsed time] = {elapsed}")

            if isinstance(score, list):
                score, ut_score, mypy_score, scpd_score = score
            else:
                ut_score = 0.0
                mypy_score = 0.0
                scpd_score = 0.0
            security_scores.append(float(scpd_score))

            if valid_response_length > 0:
                last_pos = valid_response_length - 1
                reward_tensor[i, last_pos] = float(score)
                reward_tensor_ut[i, last_pos] = float(ut_score)
                reward_tensor_mypy[i, last_pos] = float(mypy_score)
                reward_tensor_scpd[i, last_pos] = float(scpd_score)

            data_source = x["data_source"]
            if data_source not in already_print_data_sources:
                already_print_data_sources[data_source] = 0

            if already_print_data_sources[data_source] < self.num_examine:
                already_print_data_sources[data_source] += 1
                print(x["sequences_str"])

        return reward_tensor, reward_tensor_ut, reward_tensor_mypy, reward_tensor_scpd



    def call_for_safecode_apps(self, data: DataProto):
        """We will expand this function gradually based on the available datasets"""

        # If there is rm score, we directly return rm score. Otherwise, we compute via rm_score_fn
        if "rm_scores" in data.batch.keys():
            return data.batch["rm_scores"]

        reward_tensor = torch.zeros_like(data.batch["responses"], dtype=torch.float32)
        
        reward_tensor_placeholder = torch.zeros_like(data.batch['responses'], dtype=torch.float32)

        already_print_data_sources = {}

        compute_score_args = []

        for i in range(len(data)):
            data_item = data[i]  # DataProtoItem

            prompt_ids = data_item.batch["prompts"]

            prompt_length = prompt_ids.shape[-1]

            valid_prompt_length = data_item.batch["attention_mask"][
                :prompt_length
            ].sum()
            valid_prompt_ids = prompt_ids[-valid_prompt_length:]

            response_ids = data_item.batch["responses"]
            valid_response_length = data_item.batch["attention_mask"][
                prompt_length:
            ].sum()
            valid_response_ids = response_ids[:valid_response_length]

            # decode
            # sequences = torch.cat((valid_prompt_ids, valid_response_ids))
            # sequences_str = self.tokenizer.decode(sequences)
            # NOTE: otherwise we can always get some code snippets from the prompt
            sequences_str = self.tokenizer.decode(valid_response_ids)

            ground_truth = data_item.non_tensor_batch["reward_model"]["ground_truth"]

            data_source = data_item.non_tensor_batch["data_source"]

            extra_info = data_item.non_tensor_batch.get("extra_info", None)
            extra_info = self._extra_info_with_rollout_metadata(extra_info, i, data_source)

            compute_score_args.append(
                [data_source, sequences_str, ground_truth, extra_info, int(valid_response_length.item())]
            )

        # batched scoring with multiprocessing
        num_processes = self.num_processes
        start_time = time.time()
        formatted_start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"[DEBUG] Using {num_processes} processes for scoring {len(compute_score_args)} samples (start time: {formatted_start_time})"
        )

        with multiprocessing.Pool(processes=num_processes) as pool:

            mp_task = pool.starmap_async(
                self.compute_score_with_timeout, compute_score_args
            )

            try:
                scores = mp_task.get(timeout=2400)
            except multiprocessing.TimeoutError as e:
                print("Global timeout reached! Terminating all processes...")
                pool.terminate()
                for p in pool._pool:
                    p.terminate()
                scores = [0.0 for _ in range(len(compute_score_args))]
            except Exception as e:
                print(
                    f"Unexpected error in batched reward computing. Setting all as 0.: {e}"
                )
                pool.terminate()
                scores = [0.0 for _ in range(len(compute_score_args))]
            finally:
                pool.close()
                pool.join()

            # scores = mp_task.get(timeout=2400)
            # pool.terminate()
            # pool.close()
            # pool.join()

        end_time = time.time()
        used_time = round(end_time - start_time)
        formatted_used_time = str(datetime.timedelta(seconds=used_time))
        numeric_scores = [float(score[0]) if isinstance(score, list) else float(score) for score in scores]
        print(
            f"[DEBUG] Finished scoring {len(scores)} samples (average score: {round(sum(numeric_scores) / len(numeric_scores), 4)}, eclapsed time: {formatted_used_time})"
        )

        for i, (
            score,
            (data_source, sequences_str, ground_truth, extra_info, valid_response_length),
        ) in enumerate(zip(scores, compute_score_args)):
            # score = self.compute_score(
            #     data_source=data_source,
            #     solution_str=sequences_str,
            #     ground_truth=ground_truth,
            #     extra_info=extra_info,
            # )
            if isinstance(score, list):
                score = score[0]

            if valid_response_length > 0:
                reward_tensor[i, valid_response_length - 1] = score

            if data_source not in already_print_data_sources:
                already_print_data_sources[data_source] = 0

            if already_print_data_sources[data_source] < self.num_examine:
                already_print_data_sources[data_source] += 1
                print(sequences_str)

        return reward_tensor, reward_tensor_placeholder, reward_tensor_placeholder, reward_tensor_placeholder
