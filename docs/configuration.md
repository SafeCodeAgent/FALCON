# Configuration reference

Every setting, where to set it, what it accepts, and how it is applied. All
settings have working defaults, so the plugin runs with no configuration at all.

## Where settings come from

Settings are resolved in this order; a later source overrides an earlier one:

1. **Built-in defaults** (below).
2. **Settings UI** — `/plugin` → attacker-verifier → **Configure**, or the
   attacker-verifier rows in `/config`. Saved to `pluginConfigs` in your
   `settings.json` under the key `attacker-verifier@attacker-verifier`.
3. **Per-run arguments** typed after the command, for a single run.

An optional project file `.attacker-verifier/config.json` at the repo root can
also set engine-level values (probe limits, `max_targets`, and the `execution`
sandbox block); per-run arguments still override it.

## The settings

| Key | UI control | Accepts | Default | Applies to |
|---|---|---|---|---|
| `attacker` | dropdown | `main coding agent`, `opus`, `sonnet`, `haiku` | `main coding agent` | both commands |
| `attacker_effort` | dropdown | `inherit`, `low`, `medium`, `high`, `xhigh`, `max` | `inherit` | both commands |
| `verifier` | dropdown | `main coding agent`, `opus`, `sonnet`, `haiku` | `main coding agent` | both commands |
| `verifier_effort` | dropdown | `inherit`, `low`, `medium`, `high`, `xhigh`, `max` | `inherit` | both commands |
| `probes_min` | number | 1–100 | 5 | both commands |
| `probes_max` | number | 1–100 | 10 | both commands |
| `num_turns` | number | 1–10 | 2 | `/secure-code-generation` only |
| `max_targets` | number | 1–200 | 20 | both commands |

Per-run argument equivalents: `--attacker`, `--attacker-effort`, `--verifier`,
`--verifier-effort`, `--probes MIN-MAX`, `--turns N`, `--max-targets N`, and
`--scope whole|changed|path`.

## How the model setting works

The attacker and verifier are run through Claude Code's **subagent model
override**, which accepts a **model family** — `opus`, `sonnet`, or `haiku` — and
resolves it to the **latest** model of that family at run time.

- Picking `opus` always uses the current Opus; `sonnet` the current Sonnet; and
  so on. Nothing is version-pinned, so the choice never goes stale and needs no
  manual updating. This is the "always the latest model" behaviour.
- The list is families rather than specific version strings on purpose: the
  delegation mechanism takes families, and a pinned string such as `opus 5.5`
  would neither be accepted nor auto-update.
- `main coding agent` does **not** delegate: it runs the role inline on whatever
  model and effort your session is currently using.

## How reasoning effort works

- `inherit` uses your current session effort.
- Any other level (`low` … `max`) sets the effort for that role **when it runs on
  a chosen model** (i.e. when the model is `opus`/`sonnet`/`haiku`).
- When a role is `main coding agent`, it always uses the session effort, so set a
  model for that role if you want the effort choice to take effect.

## The sandbox (`execution`)

How probes execute is decided once per session (the plugin asks on first use)
and recorded separately; it is not one of the saved options above. You can also
pin it in `.attacker-verifier/config.json`:

```json
{ "execution": { "mode": "host" } }
```

or, for a container:

```json
{ "execution": { "mode": "docker", "image": "python:3.12-slim", "workdir": "/work" } }
```

`mode` is `host` (run under the current session's permissions) or `docker`
(fresh container per probe from `image`, or exec into a running `container`).
