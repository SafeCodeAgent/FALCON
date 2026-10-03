---
name: check-code-security
description: >-
  Audit code in this repository for security vulnerabilities by generating
  adversarial proof-of-concept probes, running them in a sandbox, and judging
  the resulting execution traces. Reports which parts of the repository are
  unsafe and writes a Markdown report named with the repo and a timestamp. Use
  when the user wants to check, audit, or find security issues in existing code.
argument-hint: "[path] [--probes 5-10] [--attacker main|agent] [--verifier main|agent] [--scope whole|changed|path]"
disable-model-invocation: false
---

# Check code security

Audit code by attacking it and judging what it actually does at runtime, not by
reading it. You run one attack → verify pass over the chosen scope and report
the parts of the repository that are unsafe.

Repo root is `${CLAUDE_PROJECT_DIR}`. The user's arguments are: `$ARGUMENTS`.

## 1. Sandbox (first run in the session)

Follow `${CLAUDE_PLUGIN_ROOT}/docs/sandbox.md` to settle how probes execute and
record it for the session. Do this before running any probe.

## 2. Decide the scope

- If the user named a path, a file, or specific functions (in `$ARGUMENTS` or
  earlier in the conversation), use `--scope path --path <that>` (or
  `--scope changed` if they asked for just their changes).
- **If the user gave no target at all, ask them** with `AskUserQuestion`, two
  options:
  1. **Tell me what to check** — they name the file, directory, or functions to
     focus on. Use `--scope path` with what they give.
  2. **Scan the whole repository (filtered)** — attack all non-test source,
     ranked by security relevance, up to `max_targets`. Use `--scope whole`.

Note any non-Python files in scope; pass them to `finalize --skipped` so the
report records what was not attacked. This version attacks Python.

## 3. Run one attack → verify pass

Follow `${CLAUDE_PLUGIN_ROOT}/docs/attack-verify-loop.md` with `N = 1` turn
(no repair). Build `CONFIG_JSON` from the session execution block plus any
`--probes`, `--attacker`, `--verifier`, `--max-targets` the user passed. Keep
the user informed with the progress line from that document at each step.

## 4. Write the report and summarise

In step 5 (finalize), write the report into the repo root with the deterministic
name `<repo>_<timestamp>.md`, e.g.:

```
--out "${CLAUDE_PROJECT_DIR}/$(basename "${CLAUDE_PROJECT_DIR}")_$(date +%Y%m%d-%H%M%S).md"
```

Then give the user a short terminal summary:

- the overall verdict (**INSECURE** / **SECURE** / **NO EVIDENCE**),
- for each insecure finding: the location (`file::symbol`), the weakness, and
  the one-line reason,
- the path to the written report.

Be faithful to the result: a secure verdict means no admitted probe exposed a
violation under the budget used, not that the code is proven safe. If findings
exist, offer to fix them (that is what `/secure-code-generation` does), but do
not change code in this skill unless the user asks.
