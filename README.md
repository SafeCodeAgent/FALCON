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

Everything has a working default. There are three ways to configure, and they
override each other in this order (later wins): built-in defaults → settings UI
→ per-run arguments.

### Settings UI (easiest — no typing in the prompt)

Open **`/plugin`** → **attacker-verifier** → **Configure** (or the
attacker-verifier rows in **`/config`**). You get editable fields:

| Setting | Control | Options | Default |
|---|---|---|---|
| **Attacker model** | dropdown | `main coding agent`, `opus`, `sonnet`, `haiku` | `main coding agent` |
| **Attacker reasoning effort** | dropdown | `inherit`, `low`, `medium`, `high`, `xhigh`, `max` | `inherit` |
| **Verifier model** (trace judge) | dropdown | `main coding agent`, `opus`, `sonnet`, `haiku` | `main coding agent` |
| **Verifier reasoning effort** | dropdown | `inherit`, `low`, `medium`, `high`, `xhigh`, `max` | `inherit` |
| **Probes per target (min)** | number | 1–100 | 5 |
| **Probes per target (max)** | number | 1–100 | 10 |
| **Repair turns** (`/secure-code-generation`) | number | 1–10 | 2 |
| **Max targets per run** | number | 1–200 | 20 |

Settings are saved and reused for every run until you change them.

**About the model options (why families, not `opus 5.5`).** The attacker and
verifier roles are run through Claude Code's subagent model override, which takes
a **model family** — `opus`, `sonnet`, or `haiku` — and always resolves it to the
**latest** model of that family. So picking `opus` tracks the current Opus
automatically: there is no pinned version to maintain and nothing goes stale.
This is why the list is families rather than specific version strings (a pinned
`opus 5.5` would not be accepted by the delegation mechanism and would have to be
updated by hand). `main coding agent` keeps the role inline on whatever model and
effort your session is already using.

**Reasoning effort.** `inherit` uses your current session effort. Choosing a
level (`low` … `max`) sets the effort for that role when it runs on a chosen
model. If a role is set to `main coding agent`, it always uses the session
effort, so the effort dropdown applies once you pick a model for that role.

> Note: the number fields show their current saved value. On a brand-new install
> some Claude Code builds render the number boxes empty until first saved — the
> effective defaults are still those in the table above (5, 10, 2, 20). Click
> **Save configuration** once to write them in explicitly.

### Per-run arguments (override the settings for one call)

```
/check-code-security src/ --probes 8-12 --attacker opus --verifier sonnet
/secure-code-generation implement the import --turns 3
```

| Argument | Meaning |
|---|---|
| `--probes MIN-MAX` | probe budget per target |
| `--attacker <main coding agent\|opus\|sonnet\|haiku>` | who writes probes |
| `--verifier <main coding agent\|opus\|sonnet\|haiku>` | who judges undecided traces |
| `--attacker-effort <inherit\|low\|medium\|high\|xhigh\|max>` | attacker reasoning effort |
| `--verifier-effort <inherit\|low\|medium\|high\|xhigh\|max>` | verifier reasoning effort |
| `--turns N` | attack → verify → repair cycles (`/secure-code-generation`) |
| `--max-targets N` | cap on how many functions a run attacks |
| `--scope whole\|changed\|path` | what to attack |

**Attacker and verifier as agents.** By default the main coding agent plays both
roles inline. Choosing a model family delegates to the dedicated subagents
(`attacker-verifier:attacker`, `attacker-verifier:verifier`) on the latest model
of that family, at the chosen reasoning effort. The attacker is a genuine agent:
it may read the code and the repository and iterate for up to 20 turns before
committing its probes.

For the complete, explicit reference of every setting, see
[docs/configuration.md](docs/configuration.md).

### Project file (optional, committed with the repo)

Create `.attacker-verifier/config.json` at your repo root for engine-level
defaults such as the sandbox and probe limits:

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
