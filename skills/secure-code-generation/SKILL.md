---
name: secure-code-generation
description: >-
  Generate or edit code to satisfy a request, then harden it against security
  vulnerabilities by repeatedly attacking it with adversarial proof-of-concept
  probes, judging the execution traces, and repairing any violation found. Runs
  a configurable number of attack-verify-repair turns and returns code that is
  both functional and secure. Use when the user asks to write, implement, or
  change code and wants it to be secure.
argument-hint: "<what to build> [--turns 2] [--probes 5-10] [--attacker opus|sonnet|haiku] [--verifier opus|sonnet|haiku]"
disable-model-invocation: false
---

# Secure code generation

Write the code the user asked for, then make it withstand attack. After an
initial implementation, run up to `num_turns` cycles of attack → verify →
repair, grounding each repair in a concrete counterexample rather than a hunch.

Repo root is `${CLAUDE_PROJECT_DIR}`. The user's arguments are: `$ARGUMENTS`.

## Configuration

Effort, probe counts, and repair turns come from the plugin settings (`/config`).
The in-effect values are:

- Attacker effort: `${user_config.attacker_effort}`
- Verifier effort: `${user_config.verifier_effort}`
- Probes per target: `${user_config.probes_min}`–`${user_config.probes_max}`
- Repair turns: `${user_config.num_turns}`
- Max targets: `${user_config.max_targets}`

The attacker and verifier **models** are read from the repo config file
`${CLAUDE_PROJECT_DIR}/.attacker-verifier/config.json` (set with
`/attacker-verifier:configure`). Read its `attacker` and `verifier` keys; if the
file or a key is absent, the model is `main` (run inline on the session model).
A per-run argument overrides the saved choice: resolve `--attacker <name>` or
`--verifier <name>` with
`python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" resolve-model "<name>"`.

Apply them:
- `num_turns` is the number of attack → verify → repair cycles (below).
- Build `CONFIG_JSON` with `probes_min`, `probes_max`, `max_targets`, plus the
  `execution` block from the session marker (step 1).
- **Attacker:** if the model is `main`, play the attacker inline on the current
  session model. Otherwise it is a model id — delegate to the
  `attacker-verifier:attacker` subagent via the Agent tool with `model` set to
  that id (it runs up to 20 turns); if the attacker effort is not `inherit`, run
  it at that effort.
- **Verifier:** if the model is `main`, judge traces inline. Otherwise delegate
  to the `attacker-verifier:verifier` subagent with `model` set to that id, at
  the verifier effort when it is not `inherit`.

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

Let `N = num_turns` from the Configuration section (`--turns` overrides). Follow
`${CLAUDE_PLUGIN_ROOT}/docs/attack-verify-loop.md` for each turn, with
`--scope changed` so the attacker targets what you just wrote (fall back to
`--scope path` on the touched files if there is no git history), using the
attacker, verifier, probe, and target settings from the Configuration section.

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
