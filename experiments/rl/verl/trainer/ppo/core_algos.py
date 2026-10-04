# Copyright 2024 Bytedance Ltd. and/or its affiliates
# Copyright 2022 The HuggingFace Team. All rights reserved.
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
"""
Core functions to implement PPO algorithms.
The function implemented in this file should be used by trainer with different distributed strategies to
implement PPO
"""

import numpy as np
import torch
from collections import defaultdict

import verl.utils.torch_functional as verl_F


class AdaptiveKLController:
    """
    Adaptive KL controller described in the paper:
    https://arxiv.org/pdf/1909.08593.pdf
    """

    def __init__(self, init_kl_coef, target_kl, horizon):
        self.value = init_kl_coef
        self.target = target_kl
        self.horizon = horizon

    def update(self, current_kl, n_steps):
        target = self.target
        proportional_error = np.clip(current_kl / target - 1, -0.2, 0.2)
        mult = 1 + proportional_error * n_steps / self.horizon
        self.value *= mult


class FixedKLController:
    """Fixed KL controller."""

    def __init__(self, kl_coef):
        self.value = kl_coef

    def update(self, current_kl, n_steps):
        pass


def get_kl_controller(config):
    if config.critic.kl_ctrl.type == 'fixed':
        kl_ctrl = FixedKLController(kl_coef=config.critic.kl_ctrl.kl_coef)
    elif config.critic.kl_ctrl.type == 'adaptive':
        assert config.kl_ctrl.horizon > 0, f'horizon must be larger than 0. Got {config.critic.kl_ctrl.horizon}'
        kl_ctrl = AdaptiveKLController(init_kl_coef=config.critic.kl_ctrl.kl_coef,
                                       target_kl=config.critic.kl_ctrl.target_kl,
                                       horizon=config.critic.kl_ctrl.horizon)
    else:
        raise ValueError('Unknown kl_ctrl type')

    return kl_ctrl


def compute_gae_advantage_return(token_level_rewards: torch.Tensor, values: torch.Tensor, eos_mask: torch.Tensor,
                                 gamma: torch.Tensor, lam: torch.Tensor):
    """Adapted from https://github.com/huggingface/trl/blob/main/trl/trainer/ppo_trainer.py

    Args:
        token_level_rewards: `(torch.Tensor)`
            shape: (bs, response_length)
        values: `(torch.Tensor)`
            shape: (bs, response_length)
        eos_mask: `(torch.Tensor)`
            shape: (bs, response_length). [EOS] mask. The token after [EOS] have mask zero.
        gamma: `(float)`
            discounted factor used in RL
        lam: `(float)`
            lambda value when computing Generalized Advantage Estimation (https://arxiv.org/abs/1506.02438)

    Returns:
        advantages: `(torch.Tensor)`
            shape: (bs, response_length)
        Returns: `(torch.Tensor)`
            shape: (bs, response_length)

    """
    with torch.no_grad():
        lastgaelam = 0
        advantages_reversed = []
        gen_len = token_level_rewards.shape[-1]

        for t in reversed(range(gen_len)):
            nextvalues = values[:, t + 1] if t < gen_len - 1 else 0.0
            delta = token_level_rewards[:, t] + gamma * nextvalues - values[:, t]
            lastgaelam = delta + gamma * lam * lastgaelam
            advantages_reversed.append(lastgaelam)
        advantages = torch.stack(advantages_reversed[::-1], dim=1)

        returns = advantages + values
        advantages = verl_F.masked_whiten(advantages, eos_mask)
    return advantages, returns


# NOTE(sgm): this implementation only consider outcome supervision, where the reward is a scalar.
def compute_grpo_outcome_advantage(token_level_rewards: torch.Tensor,
                                   eos_mask: torch.Tensor,
                                   index: torch.Tensor,
                                   epsilon: float = 1e-6):
    """
    Compute advantage for GRPO, operating only on Outcome reward 
    (with only one scalar reward for each response).
    Args:
        token_level_rewards: `(torch.Tensor)`
            shape: (bs, response_length)
        eos_mask: `(torch.Tensor)`
            shape: (bs, response_length)
    
    Returns:
        advantages: `(torch.Tensor)`
            shape: (bs, response_length)
        Returns: `(torch.Tensor)`
            shape: (bs, response_length)
    """
    response_length = token_level_rewards.shape[-1]
    scores = token_level_rewards.sum(dim=-1)
    id2score = defaultdict(list)
    id2mean = {}
    id2std = {}

    with torch.no_grad():
        bsz = scores.shape[0]
        for i in range(bsz):
            id2score[index[i]].append(scores[i])
        for idx in id2score:
            if len(id2score[idx]) == 1:
                id2mean[idx] = torch.tensor(0.0)
                id2std[idx] = torch.tensor(1.0)
            elif len(id2score[idx]) > 1:
                id2mean[idx] = torch.mean(torch.tensor(id2score[idx]))
                id2std[idx] = torch.std(torch.tensor([id2score[idx]]))
            else:
                raise ValueError(f"no score in prompt index: {idx}")
        for i in range(bsz):
            scores[i] = (scores[i] - id2mean[index[i]]) / (id2std[index[i]] + epsilon)
        scores = scores.unsqueeze(-1).tile([1, response_length]) * eos_mask

    means_all = torch.stack([v.detach().float().cpu() for v in id2mean.values()])
    stds_all  = torch.stack([v.detach().float().cpu() for v in id2std.values()])

    print(f"[mean reward of group] num_keys={len(id2mean)} | mean={means_all.mean().item():.6f} | std={means_all.std().item():.6f} "
        f"| min={means_all.min().item():.6f} | max={means_all.max().item():.6f}")

    print(f"[std reward of group] num_keys={len(id2std)}  | mean={stds_all.mean().item():.6f}  | std={stds_all.std().item():.6f}  "
        f"| min={stds_all.min().item():.6f}  | max={stds_all.max().item():.6f}")

    return scores, scores

@torch.no_grad()
def print_masked_stats(tag: str, x: torch.Tensor, mask: torch.Tensor, eps: float = 1e-6):
    """
    Prints global (over all valid tokens) and per-token (over batch) stats.
    x, mask: (B, T). mask is 0/1.
    """
    x_f = x.float()
    m_f = mask.float()

    # Global stats over all valid entries
    cnt = m_f.sum()
    if cnt.item() == 0:
        print(f"{tag}: no valid tokens (mask sum = 0)")
        return

    sum_x = (x_f * m_f).sum()
    mean_g = sum_x / cnt

    var_g = (((x_f - mean_g) ** 2) * m_f).sum() / cnt
    std_g = torch.sqrt(var_g + eps)

    x_min = x_f.masked_fill(m_f == 0, float("inf")).min()
    x_max = x_f.masked_fill(m_f == 0, float("-inf")).max()

    # Per-token stats (for each t, mean/std over batch)
    denom = m_f.sum(dim=0)  # (T,)
    valid_t = denom > 0

    mean_t = torch.zeros_like(denom)
    var_t = torch.zeros_like(denom)

    mean_t[valid_t] = (x_f * m_f).sum(dim=0)[valid_t] / denom[valid_t]
    centered = x_f - mean_t.unsqueeze(0)
    var_t[valid_t] = ((centered ** 2) * m_f).sum(dim=0)[valid_t] / denom[valid_t]
    std_t = torch.sqrt(var_t + eps)

    print(
        f"{tag}: global mean={mean_g.item():.6f}, std={std_g.item():.6f}, "
        f"min={x_min.item():.6f}, max={x_max.item():.6f}, count={int(cnt.item())}"
    )
    print(
        f"{tag}: per-token mean[min,max]=[{mean_t[valid_t].min().item():.6f}, {mean_t[valid_t].max().item():.6f}], "
        f"per-token std[min,max]=[{std_t[valid_t].min().item():.6f}, {std_t[valid_t].max().item():.6f}]"
    )

@torch.no_grad()
def masked_batchnorm_over_batch(x: torch.Tensor, mask: torch.Tensor, eps: float = 1e-6):
    """
    BatchNorm across the batch dimension for each time step.
    x:    (B, T)
    mask: (B, T) with 1 for valid tokens, 0 for padded
    """
    x = x * mask

    denom = mask.sum(dim=0, keepdim=True).clamp_min(1.0)  # (1, T)
    mean = (x.sum(dim=0, keepdim=True) / denom)           # (1, T)
    var  = (((x - mean) ** 2) * mask).sum(dim=0, keepdim=True) / denom  # (1, T)

    x_hat = (x - mean) / torch.sqrt(var + eps)
    return x_hat * mask

def compute_grpo_moo_outcome_advantage(token_level_rewards: torch.Tensor,
                                    util_token_level_rewards: torch.Tensor,
                                    safe_token_level_rewards: torch.Tensor,
                                   eos_mask: torch.Tensor,
                                   index: torch.Tensor,
                                   epsilon: float = 1e-6,
                                   _normalized: bool = True):
    """
    Compute advantage for GRPO, operating only on Outcome reward 
    (with only one scalar reward for each response).
    Args:
        token_level_rewards: `(torch.Tensor)`
            shape: (bs, response_length)
        util_token_level_rewards: `(torch.Tensor)`
            shape: (bs, response_length)
        safe_token_level_rewards: `(torch.Tensor)`
            shape: (bs, response_length)
        eos_mask: `(torch.Tensor)`
            shape: (bs, response_length)
    
    Returns:
        advantages: `(torch.Tensor)`
            shape: (bs, response_length)
        Returns: `(torch.Tensor)`
            shape: (bs, response_length)
    """
    response_length = token_level_rewards.shape[-1]
    scores_util = util_token_level_rewards.sum(dim=-1)
    id2score_util = defaultdict(list)
    id2mean_util = {}
    id2std_util = {}

    scores_safe = safe_token_level_rewards.sum(dim=-1)
    id2score_safe = defaultdict(list)
    id2mean_safe = {}
    id2std_safe = {}
    
    with torch.no_grad():
        ## Computing advantage for functionality
        bsz = scores_util.shape[0]
        for i in range(bsz):
            id2score_util[index[i]].append(scores_util[i])
        for idx in id2score_util:
            if len(id2score_util[idx]) == 1:
                id2mean_util[idx] = torch.tensor(0.0)
                id2std_util[idx] = torch.tensor(1.0)
            elif len(id2score_util[idx]) > 1:
                id2mean_util[idx] = torch.mean(torch.tensor(id2score_util[idx]))
                id2std_util[idx] = torch.std(torch.tensor([id2score_util[idx]]))
            else:
                raise ValueError(f"no score in prompt index: {idx}")
        for i in range(bsz):
            scores_util[i] = (scores_util[i] - id2mean_util[index[i]]) / (id2std_util[index[i]] + epsilon)
        scores_util = scores_util.unsqueeze(-1).tile([1, response_length]) * eos_mask

    # with torch.no_grad():
        ## Computing advantage for safety
        bsz = scores_safe.shape[0]
        for i in range(bsz):
            id2score_safe[index[i]].append(scores_safe[i])
        for idx in id2score_safe:
            if len(id2score_safe[idx]) == 1:
                id2mean_safe[idx] = torch.tensor(0.0)
                id2std_safe[idx] = torch.tensor(1.0)
            elif len(id2score_safe[idx]) > 1:
                id2mean_safe[idx] = torch.mean(torch.tensor(id2score_safe[idx]))
                id2std_safe[idx] = torch.std(torch.tensor([id2score_safe[idx]]))
            else:
                raise ValueError(f"no score in prompt index: {idx}")
        for i in range(bsz):
            scores_safe[i] = (scores_safe[i] - id2mean_safe[index[i]]) / (id2std_safe[index[i]] + epsilon)
        scores_safe = scores_safe.unsqueeze(-1).tile([1, response_length]) * eos_mask

        print('*'*50)
        # print(f'### scores_util before has shape = {scores_util.shape} and value = {scores_util}')
        # print(f'### scores_safe before has shape = {scores_safe.shape} and value = {scores_safe}')
        # print_masked_stats("scores_util BEFORE", scores_util, eos_mask, eps=epsilon)
        # print_masked_stats("scores_safe BEFORE", scores_safe, eos_mask, eps=epsilon)

        if _normalized == True:
            scores_util = masked_batchnorm_over_batch(scores_util, eos_mask, eps=epsilon)
            scores_safe = masked_batchnorm_over_batch(scores_safe, eos_mask, eps=epsilon)
            # print_masked_stats("scores_util AFTER ", scores_util, eos_mask, eps=epsilon)
            # print_masked_stats("scores_safe AFTER ", scores_safe, eos_mask, eps=epsilon)

            # print(f'### scores_util after normalized has shape = {scores_util.shape} and value = {scores_util}')
            # print(f'### scores_safe after normalized has shape = {scores_safe.shape} and value = {scores_safe}')

        print('*'*50)

        # Combine 2 scores
        scores = scores_util + scores_safe 
    # print(f'#### Using MOO for advantage: scores_util = {scores_util}, scores_safe = {scores_safe} => scores = {scores}')
    return scores, scores, scores_util, scores_safe


def compute_reinforce_plus_plus_outcome_advantage(token_level_rewards: torch.Tensor, eos_mask: torch.Tensor,
                                                  gamma: torch.Tensor):
    """
    Compute advantage for REINFORCE++. 
    This implementation is based on the paper: https://arxiv.org/abs/2501.03262
    Args:
        token_level_rewards: `(torch.Tensor)`
            shape: (bs, response_length)
        eos_mask: `(torch.Tensor)`
            shape: (bs, response_length)
    
    Returns:
        advantages: `(torch.Tensor)`
            shape: (bs, response_length)
        Returns: `(torch.Tensor)`
            shape: (bs, response_length)
    """

    with torch.no_grad():
        returns = torch.zeros_like(token_level_rewards)
        running_return = 0

        for t in reversed(range(token_level_rewards.shape[1])):
            running_return = token_level_rewards[:, t] + gamma * running_return
            returns[:, t] = running_return
            # Reset after EOS
            running_return = running_return * eos_mask[:, t]

        advantages = verl_F.masked_whiten(returns, eos_mask)
        advantages = advantages * eos_mask

    return advantages, returns


def compute_remax_outcome_advantage(token_level_rewards: torch.Tensor, reward_baselines: torch.Tensor,
                                    eos_mask: torch.Tensor):
    """
    Compute advantage for ReMax, operating only on Outcome reward 
    This implementation is based on the paper: https://arxiv.org/abs/2310.10505

    (with only one scalar reward for each response).
    Args:
        token_level_rewards: `(torch.Tensor)`
            shape: (bs, response_length)
        reward_baselines: `(torch.Tensor)`
            shape: (bs,)
        eos_mask: `(torch.Tensor)`
            shape: (bs, response_length)
    
    Returns:
        advantages: `(torch.Tensor)`
            shape: (bs, response_length)
        Returns: `(torch.Tensor)`
            shape: (bs, response_length)
    """
    response_length = token_level_rewards.shape[-1]
    scores = token_level_rewards.sum(dim=-1)

    with torch.no_grad():
        returns = (token_level_rewards * eos_mask).flip(dims=[-1]).cumsum(dim=-1).flip(dims=[-1])
        advantages = returns - reward_baselines.unsqueeze(-1).tile([1, response_length]) * eos_mask

    return advantages, returns


def compute_rewards(token_level_scores, old_log_prob, ref_log_prob, kl_ratio):
    kl = old_log_prob - ref_log_prob
    return token_level_scores - kl * kl_ratio


def compute_policy_loss(old_log_prob, log_prob, advantages, eos_mask, cliprange):
    """Adapted from https://github.com/huggingface/trl/blob/main/trl/trainer/ppo_trainer.py#L1122

    Args:
        old_log_prob: `(torch.Tensor)`
            shape: (bs, response_length)
        log_prob: `(torch.Tensor)`
            shape: (bs, response_length)
        advantages: `(torch.Tensor)`
            shape: (bs, response_length)
        eos_mask: `(torch.Tensor)`
            shape: (bs, response_length)
        cliprange: (float)
            The clip range used in PPO. See https://arxiv.org/abs/1707.06347

    Returns:
        pg_loss: `a scalar torch.Tensor`
            policy gradient loss computed via PPO
        pg_clipfrac: (float)
            a float number indicating the fraction of policy gradient loss being clipped

    """
    negative_approx_kl = log_prob - old_log_prob
    ratio = torch.exp(negative_approx_kl)
    ppo_kl = verl_F.masked_mean(-negative_approx_kl, eos_mask)

    pg_losses = -advantages * ratio
    pg_losses2 = -advantages * torch.clamp(ratio, 1.0 - cliprange, 1.0 + cliprange)

    pg_loss = verl_F.masked_mean(torch.max(pg_losses, pg_losses2), eos_mask)
    pg_clipfrac = verl_F.masked_mean(torch.gt(pg_losses2, pg_losses).float(), eos_mask)
    return pg_loss, pg_clipfrac, ppo_kl

def compute_policy_loss_moo(old_log_prob, log_prob, advantages, advantages_util, advantages_safe, eos_mask, cliprange, moo_algorithm=None):
    """Adapted from https://github.com/huggingface/trl/blob/main/trl/trainer/ppo_trainer.py#L1122

    Args:
        old_log_prob: `(torch.Tensor)`
            shape: (bs, response_length)
        log_prob: `(torch.Tensor)`
            shape: (bs, response_length)
        advantages: `(torch.Tensor)`
            shape: (bs, response_length)
        advantages_util: `(torch.Tensor)`
            shape: (bs, response_length)
        advantages_safe: `(torch.Tensor)`
            shape: (bs, response_length)
        eos_mask: `(torch.Tensor)`
            shape: (bs, response_length)
        cliprange: (float)
            The clip range used in PPO. See https://arxiv.org/abs/1707.06347

    Returns:
        pg_loss: `a scalar torch.Tensor`
            policy gradient loss computed via PPO
        pg_clipfrac: (float)
            a float number indicating the fraction of policy gradient loss being clipped

    """
    negative_approx_kl = log_prob - old_log_prob
    ratio = torch.exp(negative_approx_kl)
    ppo_kl = verl_F.masked_mean(-negative_approx_kl, eos_mask)

    # pg_losses = -advantages * ratio
    # pg_losses2 = -advantages * torch.clamp(ratio, 1.0 - cliprange, 1.0 + cliprange)

    # pg_loss = verl_F.masked_mean(torch.max(pg_losses, pg_losses2), eos_mask)
    # pg_clipfrac = verl_F.masked_mean(torch.gt(pg_losses2, pg_losses).float(), eos_mask)

    ## For util
    pg_losses_util = -advantages_util * ratio
    pg_losses_util2 = -advantages_util * torch.clamp(ratio, 1.0 - cliprange, 1.0 + cliprange)

    pg_loss_util = verl_F.masked_mean(torch.max(pg_losses_util, pg_losses_util2), eos_mask)
    pg_clipfrac_util = verl_F.masked_mean(torch.gt(pg_losses_util2, pg_losses_util).float(), eos_mask)

    ## For safe
    pg_losses_safe = -advantages_safe * ratio
    pg_losses_safe2 = -advantages_safe * torch.clamp(ratio, 1.0 - cliprange, 1.0 + cliprange)

    pg_loss_safe = verl_F.masked_mean(torch.max(pg_losses_safe, pg_losses_safe2), eos_mask)
    pg_clipfrac_safe = verl_F.masked_mean(torch.gt(pg_losses_safe2, pg_losses_safe).float(), eos_mask)

    # Combine

    if moo_algorithm != None:
        pg_loss, info = moo_algorithm.combine({
            "util": pg_loss_util,
            "safe": pg_loss_safe,
        })
        pass
    else:
        pg_loss = (pg_loss_util + pg_loss_safe) / 2
        # print(f'---- pg_loss_util = {pg_loss_util}; pg_loss_safe = {pg_loss_safe} => pg_loss = {pg_loss}')
    pg_clipfrac = (pg_clipfrac_util + pg_clipfrac_safe) / 2

    return pg_loss, pg_clipfrac, ppo_kl, pg_loss_util, pg_loss_safe

def compute_entropy_loss(logits, eos_mask):
    """Compute Categorical entropy loss

    Args:
        logits: `(torch.Tensor)`
            shape: (bs, response_length, vocab_size)
        eos_mask: `(torch.Tensor)`
            shape: (bs, response_length)

    Returns:
        entropy: a scalar torch.Tensor

    """
    # compute entropy
    entropy = verl_F.entropy_from_logits(logits)  # (bs, response_len)
    entropy_loss = verl_F.masked_mean(entropy, mask=eos_mask)
    return entropy_loss


def compute_value_loss(vpreds, returns, values, eos_mask, cliprange_value):
    """Compute the value loss. Copied from https://github.com/huggingface/trl/blob/main/trl/trainer/ppo_trainer.py#L1151

    Args:
        vpreds (`torch.FloatTensor`):
            Predicted values of the value head, shape (`batch_size`, `response_length`)
        values (`torch.FloatTensor`):
            Old values of value head, shape (`batch_size`, `response_length`)
        returns: (`torch.FloatTensor`):
            Ground truth returns, shape (`batch_size`, `response_length`)

    Returns:
        vf_loss: a scalar (`torch.FloatTensor`):
            value function loss
        vf_clipfrac: a float
            The ratio of vf being clipped

    """
    vpredclipped = verl_F.clip_by_value(vpreds, values - cliprange_value, values + cliprange_value)
    vf_losses1 = (vpreds - returns)**2
    vf_losses2 = (vpredclipped - returns)**2
    vf_loss = 0.5 * verl_F.masked_mean(torch.max(vf_losses1, vf_losses2), eos_mask)
    vf_clipfrac = verl_F.masked_mean(torch.gt(vf_losses2, vf_losses1).float(), eos_mask)
    return vf_loss, vf_clipfrac


def kl_penalty(logprob: torch.FloatTensor, ref_logprob: torch.FloatTensor, kl_penalty) -> torch.FloatTensor:
    """Compute KL divergence given logprob and ref_logprob.
    Copied from https://github.com/huggingface/trl/blob/main/trl/trainer/ppo_trainer.py#L1104

    Args:
        logprob:
        ref_logprob:

    Returns:

    """
    if kl_penalty == "kl":
        return logprob - ref_logprob

    if kl_penalty == "abs":
        return (logprob - ref_logprob).abs()

    if kl_penalty == "mse":
        return 0.5 * (logprob - ref_logprob).square()

    # J. Schulman. Approximating kl divergence, 2020.
    # # URL http://joschu.net/blog/kl-approx.html.
    if kl_penalty == 'low_var_kl':
        kl = ref_logprob - logprob
        ratio = torch.exp(kl)
        kld = (ratio - kl - 1).contiguous()
        return torch.clamp(kld, min=-10, max=10)

    if kl_penalty == "full":
        # so, here logprob and ref_logprob should contain the logits for every token in vocabulary
        raise NotImplementedError

    raise NotImplementedError
