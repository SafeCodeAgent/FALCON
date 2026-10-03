# Attacker-Verifier

**Counterexample-grounded security for agent-generated code, as a Claude Code plugin.**

Reading code to decide whether it is secure is hard and unreliable. Attacker-Verifier
judges code by *what it does when attacked*, not by how it looks. An **attacker**
proposes deterministic proof-of-concept probes that drive a target function with
adversarial inputs; a **faithfulness check** discards probes that would fake the
result; the admitted probes run in a **sandbox**; and a **verifier** reads the
resulting execution traces and decides, backed by concrete evidence.

It ships two slash commands:

- **`/secure-code-generation`** — write or edit code, then harden it over a few
  attack → verify → repair turns, fixing each vulnerability against a real
  counterexample.
- **`/check-code-security`** — audit existing code and report which parts of the
  repository are unsafe, with a Markdown report you can share.

Both run with **no configuration** out of the box, and expose a small set of
knobs when you want them.

---

## Install

In Claude Code:

```
/plugin marketplace add tue09/attacker-verifier
/plugin install attacker-verifier@attacker-verifier
```

That is all. The commands are then available as `/secure-code-generation` and
`/check-code-security` (and their namespaced forms `/attacker-verifier:...`).

To update later:

```
/plugin marketplace update attacker-verifier
```

Requirements: Python 3.8+ on the machine (or in your container) that runs the
probes. The engine is pure standard library — nothing to `pip install`.

---

## Usage

### Check existing code

```
/check-code-security
```

With no target, it asks whether to scan the whole repository (filtered to the
most security-relevant functions) or to focus on something you name. You can
also point it directly:

```
/check-code-security src/storage.py
/check-code-security src/ --probes 8-12
/check-code-security --scope changed        # only your uncommitted changes
```

It writes a report named `<repo>_<timestamp>.md` in the repository root and
prints a short summary of the unsafe findings.

### Generate secure code

```
/secure-code-generation add an endpoint that serves report files by name
/secure-code-generation implement the CSV import --turns 3
```

It implements the request, then attacks and repairs what it wrote for
`--turns` rounds (default 2), and tells you what it found and fixed.

---

## The first run in a session: sandbox

Probes execute real code with adversarial inputs, so they run in a sandbox. The
**first time** either command runs in a session, it asks once how to execute
probes:

- **Use an existing sandbox / Docker** — name a Docker image (a fresh container
  per probe) or a running container to exec into. Probes are isolated from your
  host.
- **Run here with current permissions** — no container; probes run under the
  permissions and sandboxing this Claude Code session already has. This is the
  default if you have no sandbox.

The choice is remembered for the rest of the session.

---

Everything has a working default. Set anything you want in the UI, or override
per run with arguments.

### Settings UI (`/config`)

Open **`/config`** (or `/plugin` → attacker-verifier → Configure). Every setting
is an editable row:

| Setting | Control | Options | Default |
|---|---|---|---|
| **Attacker model** | dropdown | `main coding agent`, `opus`, `sonnet`, `haiku` | `main coding agent` |
| **Attacker reasoning effort** | dropdown | `inherit`, `low`, `medium`, `high`, `xhigh`, `max` | `inherit` |
| **Verifier model** (trace judge) | dropdown | `main coding agent`, `opus`, `sonnet`, `haiku` | `main coding agent` |
| **Verifier reasoning effort** | dropdown | `inherit`, `low`, `medium`, `high`, `xhigh`, `max` | `inherit` |
| **Attacker max turns** | number | 1–100 | 20 |
| **Probes per target (min)** | number | 1–100 | 5 |
| **Probes per target (max)** | number | 1–100 | 10 |
| **Repair turns** (`/secure-code-generation`) | number | 1–10 | 2 |
| **Max targets per run** | number | 1–200 | 20 |

**Models.** `main coding agent` (the default) runs the role inline on your
current session model — to follow whatever model you use, leave it here and set
your session model with Claude Code's own **`/model`** picker. `opus` / `sonnet`
/ `haiku` are **families** that always resolve to the **latest** model of that
family, so the choice auto-updates when Claude Code ships a new model — nothing
is version-pinned and no plugin edit is needed. Fable is not offered.

`inherit` effort uses your current session effort; a chosen level applies when a
role runs on a family (not `main coding agent`).

**Attacker max turns** is the attacker's turn budget per target: it explores and
crafts probes for up to this many turns, then returns its probes (compelled to
return if it hasn't; the target is skipped if it produces none). This is
separate from **Max targets per run** (how many functions one run attacks) and
**Repair turns** (how many fix cycles `/secure-code-generation` runs).

> Note: on a brand-new install some Claude Code builds render the number boxes
> empty until first saved — the effective defaults are still those above
> (5, 10, 2, 20). Click **Save configuration** once to write them in explicitly.

### Per-run arguments (override the settings for one call)

```
/check-code-security src/ --probes 8-12 --attacker opus --verifier sonnet
/secure-code-generation implement the import --turns 3
```

| Argument | Meaning |
|---|---|
| `--probes MIN-MAX` | probe budget per target |
| `--attacker <main coding agent\|opus\|sonnet\|haiku>` | model for the attacker |
| `--verifier <main coding agent\|opus\|sonnet\|haiku>` | model for the verifier |
| `--attacker-effort <inherit\|low\|medium\|high\|xhigh\|max>` | attacker reasoning effort |
| `--verifier-effort <inherit\|low\|medium\|high\|xhigh\|max>` | verifier reasoning effort |
| `--attacker-max-turns N` | attacker turn budget per target |
| `--turns N` | attack → verify → repair cycles (`/secure-code-generation`) |
| `--max-targets N` | cap on how many functions a run attacks |
| `--scope whole\|changed\|path` | what to attack |

**Attacker and verifier as agents.** By default both roles run inline on the
main coding agent. Choosing a model delegates to the dedicated subagents
(`attacker-verifier:attacker`, `attacker-verifier:verifier`) on that model, at
the chosen reasoning effort. The attacker is a genuine agent: it may read the
code and the repository and iterate for up to 20 turns before committing its
probes.

For the complete, explicit reference of every setting, see
[docs/configuration.md](docs/configuration.md).

### Project file (optional, committed with the repo)

Set engine-level defaults (sandbox, probe limits) for the repo in
`.attacker-verifier/config.json`:

```json
{
  "probes_min": 5,
  "probes_max": 10,
  "max_targets": 20,
  "execution": { "mode": "host" }
}
```

---

## How it works

For each attacked target the plugin runs this pipeline:

1. **Target selection** (deterministic). Functions, methods, and classes in
   non-test files are ranked by how much security-relevant surface they touch.
2. **Attacker** (agent). Proposes deterministic probes that exercise a target
   with adversarial inputs — and *only* inputs: a probe never states an expected
   output or a verdict.
3. **Faithfulness check** (deterministic). A probe that redefines, rebinds, or
   mocks the target, or that performs the sensitive operation itself, is
   discarded before it can count as evidence. A probe that never reaches the
   target is inconclusive.
4. **Sandboxed execution** (deterministic). Each admitted probe runs in its own
   process under a tracer that records the target's activations, arguments,
   return values, exceptions, and the probe's observations.
5. **Verifier**. A deterministic **crash oracle** flags abnormal termination on
   the exercised path. Anything it cannot decide goes to a **trace judge** that
   reads the execution trace — not the source — and decides secure or insecure
   from the observed behaviour.
6. **Signal.** A target is **insecure** if any admitted probe is insecure,
   **secure** if the admitted set is non-empty and none is insecure, and
   **no-evidence** if nothing was admitted.

Each insecure verdict carries a counterexample — the probe, its trace, and the
reason — which is what `/secure-code-generation` repairs against.

---

## The report

`/check-code-security` writes a Markdown report with a fixed structure, so runs
are comparable and diffable:

1. Title and run metadata (repository, time, scope, execution mode)
2. Verdict summary with counts
3. **Insecure findings** — the unsafe parts, each with location, weakness,
   reason, evidence, and a trace excerpt
4. Per-target results table
5. Faithfulness summary (what was rejected and why)
6. Not attacked (files or languages skipped)
7. The exact configuration used

A sample is in [`docs/sample-report.md`](docs/sample-report.md).

---

## Scope and limits

- **Language.** This version attacks **Python** end to end. Files in other
  languages are listed in the report as not attacked rather than given a verdict.
- **Coverage.** A secure verdict means no admitted probe exposed a violation
  under the budget used. It is evidence of robustness against the attacks tried,
  not a proof of safety. Raise `--probes` or widen the scope for a deeper check.
- **Execution cost.** Running code is heavier than reading it; that is the price
  of grounding the verdict in real behaviour.

---

## Repository layout

```
attacker-verifier/
├── .claude-plugin/        plugin.json + marketplace.json
├── skills/                the two slash commands
├── agents/                attacker and verifier subagents
├── engine/                deterministic engine (stdlib only) + prompts
├── docs/                  shared procedures and a sample report
└── README.md
```

## License

MIT — see [LICENSE](LICENSE).
