import torch
from typing import List, Dict, Union, Tuple


class FAMO:
    """
    CPU-only FAMO:
      - All internal state stays on CPU (xi, min_losses, prev_*).
      - Each step: move only K losses to CPU for weight computation.
      - Then move weights back to the original loss device to form total_loss.
    """

    def __init__(
        self,
        num_tasks: int,
        beta: float = 1e-3,
        gamma: float = 1e-3,
        eps: float = 1e-8,
        clamp_xi: float = 10.0,
    ):
        assert num_tasks >= 2, "num_tasks must be >= 2"
        self.k = num_tasks
        self.beta = beta
        self.gamma = gamma
        self.eps = eps
        self.clamp_xi = clamp_xi

        # ALWAYS CPU state
        self.xi = torch.zeros(self.k, device="cpu", dtype=torch.float32)
        self.min_losses = torch.full((self.k,), float("inf"), device="cpu", dtype=torch.float32)

        self.prev_losses_pos = None
        self.prev_z = None

    def reset(self):
        self.xi.zero_()
        self.min_losses.fill_(float("inf"))
        self.prev_losses_pos = None
        self.prev_z = None

    def _softmax(self) -> torch.Tensor:
        return torch.softmax(self.xi, dim=0)

    @torch.no_grad()
    def _make_positive(self, losses_cpu_fp32: torch.Tensor) -> torch.Tensor:
        # losses_cpu_fp32 must be on CPU
        self.min_losses = torch.minimum(self.min_losses, losses_cpu_fp32.detach())
        return (losses_cpu_fp32 - self.min_losses) + self.eps

    @torch.no_grad()
    def _delta_softmax_times_vec(self, z: torch.Tensor, v: torch.Tensor) -> torch.Tensor:
        dot = torch.dot(z, v)
        return z * (v - dot)

    @torch.no_grad()
    def _update_logits(self, curr_losses_pos_cpu_fp32: torch.Tensor):
        if self.prev_losses_pos is None:
            return

        diff = torch.log(self.prev_losses_pos + self.eps) - torch.log(curr_losses_pos_cpu_fp32 + self.eps)
        delta = self._delta_softmax_times_vec(self.prev_z, diff)

        self.xi -= self.beta * (delta + self.gamma * self.xi)
        if self.clamp_xi is not None:
            self.xi.clamp_(-self.clamp_xi, self.clamp_xi)

    @torch.no_grad()
    def _get_weights(self, losses_pos_cpu_fp32: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        z = self._softmax()  # CPU fp32
        ratio = z / (losses_pos_cpu_fp32 + self.eps)
        w = ratio / (ratio.sum() + self.eps)
        return w, z

    def combine(
        self,
        losses: Union[List[torch.Tensor], Dict[str, torch.Tensor]],
        return_named: bool = True,
    ) -> Tuple[torch.Tensor, Dict]:
        # parse losses
        if isinstance(losses, dict):
            names = list(losses.keys())
            loss_list = [losses[n] for n in names]
        else:
            names = [f"task_{i}" for i in range(len(losses))]
            loss_list = list(losses)

        assert len(loss_list) == self.k, f"Expected {self.k} losses, got {len(loss_list)}"
        assert all(isinstance(x, torch.Tensor) for x in loss_list), "All losses must be torch.Tensor"

        # raw losses (keep grad)
        L = torch.stack(loss_list)  # device could be cuda or cpu
        L_device = L.device
        L_dtype = L.dtype

        # move only K scalars to CPU for FAMO math
        L_cpu_fp32 = L.detach().to(device="cpu", dtype=torch.float32)

        with torch.no_grad():
            L_pos_cpu = self._make_positive(L_cpu_fp32)
            self._update_logits(L_pos_cpu)
            w_cpu, z_cpu = self._get_weights(L_pos_cpu)

            self.prev_losses_pos = L_pos_cpu.detach()
            self.prev_z = z_cpu.detach()

        # bring weights back to loss device to combine with gradient-carrying L
        w = w_cpu.to(device=L_device, dtype=L_dtype)
        total_loss = (w.detach() * L).sum()

        info = {
            "weights": w_cpu.detach().cpu(),
            "probs": z_cpu.detach().cpu(),
            "xi": self.xi.detach().cpu(),
            "losses_raw": L.detach().cpu(),
            "losses_pos": L_pos_cpu.detach().cpu(),
        }

        if return_named:
            info_named = {}
            for i, n in enumerate(names):
                info_named[n] = {
                    "w": float(w_cpu[i].item()),
                    "z": float(z_cpu[i].item()),
                    "xi": float(self.xi[i].item()),
                    "loss": float(L_cpu_fp32[i].item()),
                }
            info["named"] = info_named

        return total_loss, info


import torch
from typing import List, Dict, Union, Tuple


class DWA:
    """
    Dynamic Weight Average (DWA) - CPU-only.
    - Keep buffer + weights on CPU.
    - Each step copy K loss scalars to CPU, update weights, then copy weights back to loss device.
    """

    def __init__(
        self,
        num_tasks: int,
        iteration_window: int = 25,
        temp: float = 2.0,
        eps: float = 1e-8,
    ):
        assert num_tasks >= 2
        assert iteration_window >= 1
        assert temp > 0

        self.k = num_tasks
        self.iteration_window = iteration_window
        self.temp = temp
        self.eps = eps

        self.running_iterations = 0

        # FIFO history buffer on CPU: shape (2W, K)
        self.costs = torch.ones((2 * iteration_window, num_tasks), device="cpu", dtype=torch.float32)

        # weights on CPU, sum approx = K
        self.weights = torch.ones((num_tasks,), device="cpu", dtype=torch.float32)

    def reset(self):
        self.running_iterations = 0
        self.costs.fill_(1.0)
        self.weights.fill_(1.0)

    @torch.no_grad()
    def _update_costs_fifo(self, cost_cpu_fp32: torch.Tensor):
        """
        Safe FIFO shift:
            costs[:-1] <- costs[1:]  (needs clone to avoid overlap)
            costs[-1]  <- cost
        """
        # clone RHS to avoid overlapping write
        self.costs[:-1, :].copy_(self.costs[1:, :].clone())
        self.costs[-1, :].copy_(cost_cpu_fp32)

    @torch.no_grad()
    def _compute_weights(self) -> torch.Tensor:
        """
        Smooth DWA using two windows:
          ws = mean(new) / mean(old)
          weights = K * softmax(ws / T)
        """
        W = self.iteration_window
        mean_old = self.costs[:W, :].mean(dim=0)            # (K,)
        mean_new = self.costs[W:, :].mean(dim=0)            # (K,)
        ws = mean_new / (mean_old + self.eps)              # (K,)

        logits = ws / self.temp
        logits = logits - logits.max()                     # stability
        exp_logits = torch.exp(logits)
        w = (self.k * exp_logits) / (exp_logits.sum() + self.eps)
        return w  # (K,)

    def combine(
        self,
        losses: Union[List[torch.Tensor], Dict[str, torch.Tensor]],
        return_named: bool = True,
        reduction: str = "sum",  # "sum" recommended
    ) -> Tuple[torch.Tensor, Dict]:

        if isinstance(losses, dict):
            names = list(losses.keys())
            loss_list = [losses[n] for n in names]
        else:
            names = [f"task_{i}" for i in range(len(losses))]
            loss_list = list(losses)

        assert len(loss_list) == self.k, f"Expected {self.k} losses, got {len(loss_list)}"

        # raw losses (keep grad)
        L = torch.stack(loss_list)          # (K,), on GPU or CPU
        L_device = L.device
        L_dtype = L.dtype

        # move only K scalars to CPU
        cost_cpu = L.detach().to(device="cpu", dtype=torch.float32)

        with torch.no_grad():
            self._update_costs_fifo(cost_cpu)

            if self.running_iterations >= self.iteration_window:
                self.weights = self._compute_weights()

        # move weights to same device as loss for combining
        w = self.weights.to(device=L_device, dtype=L_dtype)

        if reduction == "mean":
            total_loss = (w.detach() * L).mean()
        else:
            total_loss = (w.detach() * L).sum()

        info = {
            "weights": self.weights.detach().cpu(),
            "losses_raw": L.detach().cpu(),
            "running_iterations": int(self.running_iterations),
        }

        if return_named:
            info["named"] = {
                names[i]: {"w": float(self.weights[i].item()), "loss": float(cost_cpu[i].item())}
                for i in range(self.k)
            }

        self.running_iterations += 1
        return total_loss, info


import torch
from typing import List, Dict, Union, Tuple


class REVERSE:
    """
    Basic reverse combiner:
      total_loss = loss_0 - loss_1 - loss_2 - ... - loss_{K-1}

    Accepts:
      - list of losses: [l0, l1, ...]
      - dict of losses: {"name0": l0, "name1": l1, ...}
    """

    def __init__(self, num_tasks: int):
        assert num_tasks >= 1, "num_tasks must be >= 1"
        self.k = num_tasks

    def combine(
        self,
        losses: Union[List[torch.Tensor], Dict[str, torch.Tensor]],
        return_named: bool = True,
    ) -> Tuple[torch.Tensor, Dict]:
        if isinstance(losses, dict):
            names = list(losses.keys())
            loss_list = [losses[n] for n in names]
        else:
            names = [f"task_{i}" for i in range(len(losses))]
            loss_list = list(losses)

        assert len(loss_list) == self.k, f"Expected {self.k} losses, got {len(loss_list)}"
        assert all(isinstance(x, torch.Tensor) for x in loss_list), "All losses must be torch.Tensor"

        L = torch.stack(loss_list)  # keeps grad
        total_loss = L[0] - 0.2*L[1:].sum() if self.k > 1 else L[0]

        info = {
            "losses": L.detach().cpu(),
            "total_loss": float(total_loss.detach().cpu().item()),
        }

        if return_named:
            info["named"] = {names[i]: float(L[i].detach().cpu().item()) for i in range(self.k)}

        return total_loss, info
