---
name: secure-code-generation
description: >-
  Generate or edit code to satisfy a request, then harden it against security
  vulnerabilities by repeatedly attacking it with adversarial proof-of-concept
  probes, judging the execution traces, and repairing any violation found. Runs
  a configurable number of attack-verify-repair turns and returns code that is
  both functional and secure. Use when the user asks to write, implement, or
  change code and wants it to be secure.
argument-hint: "<what to build> [--turns 2] [--probes 5-10] [--attacker main|agent] [--verifier main|agent]"
disable-model-invocation: false
---

# Secure code generation

Write the code the user asked for, then make it withstand attack. After an
initial implementation, run up to `num_turns` cycles of attack → verify →
repair, grounding each repair in a concrete counterexample rather than a hunch.

Repo root is `${CLAUDE_PROJECT_DIR}`. The user's arguments are: `$ARGUMENTS`.

## 1. Sandbox (first run in the session)

Follow `${CLAUDE_PLUGIN_ROOT}/docs/sandbox.md` to settle how probes execute and
record it for the session. Do this before running any probe.

## 2. Implement the request — main coding agent

Build or edit the code the user asked for, normally, as the main coding agent.
Keep it functional: if the project has tests or an obvious way to exercise the
feature, use it. Note which files and symbols you changed — those are what the
attacker will target.

Progress: `turn 0/<N> · main coding agent · implemented <summary>`.

## 3. Attack → verify → repair loop

Let `N = num_turns` (default 2; `--turns` overrides). Follow
`${CLAUDE_PLUGIN_ROOT}/docs/attack-verify-loop.md` for each turn, with
`--scope changed` so the attacker targets what you just wrote (fall back to
`--scope path` on the touched files if there is no git history). Build
`CONFIG_JSON` from the session execution block plus any `--probes`,
`--attacker`, `--verifier` the user passed.

For each turn `t` from 1 to `N`:

1. Run steps 1–5 of the loop (select-targets → attacker → check → verifier →
   finalize), writing intermediate files under the run directory. Omit `--out`
   on finalize; read `final.json`.
2. If the signal is **secure** or **no-evidence** with no counterexamples, stop
   early — the code withstood this turn's attack.
3. If there are counterexamples, **repair as the main coding agent**: for each
   finding, read its probe, trace, and reason, and fix the root cause in the
   code under test (validate/sanitise input, enforce the boundary, use the safe
   API). Do not weaken the probe, special-case the canary, or silence the
   symptom. Re-run functional checks so the fix keeps the feature working.

   Progress: `turn t/N · main coding agent · repairing F finding(s)`.

Stop after `N` turns or when a turn finds nothing. Keep the last working version
of the code.

## 4. Report back

Summarise for the user:

- what you built,
- for each turn: how many findings were found and fixed,
- the final state (secure under the budget used, or the findings that remain if
  the turn budget ran out — be honest about residual risk),
- note that a clean result means no admitted probe exposed a violation under the
  configured budget, not a proof of safety. Offer to raise `--turns` or
  `--probes` for a deeper pass.

If the user asks for a written report, run `finalize` once more with
`--out "<repo>_<timestamp>.md"` as in `/check-code-security`.
