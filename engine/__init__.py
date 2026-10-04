"""attacker-verifier engine.

A small, dependency-free toolkit that drives the deterministic half of the
attacker/verifier loop: selecting attack targets, screening proof-of-concept
probes for faithfulness, executing them under a tracer in a sandbox, and
turning the resulting execution traces into a verdict and a report.

The reasoning half of the loop -- proposing probes and judging the traces that
the deterministic stages leave undecided -- is carried out by the coding agent
driving this engine, guided by the prompts in ``engine/prompts``.
"""

__version__ = "0.2.0"
