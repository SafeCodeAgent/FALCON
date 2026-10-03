---
name: configure
description: >-
  Choose the attacker and verifier models for the attacker-verifier plugin from
  Claude Code's live model list, and save the choice for this repository. Use
  when the user wants to set, change, or see which models the attacker and
  verifier run on.
argument-hint: "(interactive)"
disable-model-invocation: false
---

# Configure attacker-verifier models

Set which model the **attacker** and the **verifier** run on. The list is read
live from Claude Code's own model catalog, so it always matches what `/model`
offers (the Fable family is excluded). Nothing here is hardcoded: when Claude
Code updates its models, these choices update with it.

Reasoning effort and probe counts are separate and live in `/config` (or
`/plugin` → attacker-verifier → Configure); this command only sets the models.

## Steps

1. **Read the live model list:**

   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" list-models
   ```

   This prints the current models as `{id, name, quick_select, section}`, Fable
   excluded. If `available` is `false` (catalog not cached yet), tell the user
   the list could not be read and that you will offer the family aliases
   `opus` / `sonnet` / `haiku` instead (Claude Code resolves each to its latest
   model), or they can set the session model with `/model`.

2. **Ask the user to choose**, with `AskUserQuestion`, two questions:

   - **Attacker model** — options built from the live list: `main coding agent`
     first, then the `quick_select` model names. The user can pick **Other** to
     type any name the list printed (e.g. an overflow model like `Opus 5`).
   - **Verifier model** — same options.

   Do not invent model names; build the options only from what step 1 printed.
   `main coding agent` means run the role inline on the current session model
   (no delegation).

3. **Resolve each choice to a model id** (skip for `main coding agent`):

   ```
   python3 "${CLAUDE_PLUGIN_ROOT}/engine/cli.py" resolve-model "<the chosen name>"
   ```

   `main coding agent` resolves to `main`. If a typed name does not resolve,
   show the user the available names from step 1 and ask again.

4. **Save to the repository config** at `${CLAUDE_PROJECT_DIR}/.attacker-verifier/config.json`,
   merging with any existing content (create the file and directory if needed).
   Set `attacker` and `verifier` to the resolved value (`main`, or a model id):

   ```json
   { "attacker": "main", "verifier": "claude-sonnet-5-5" }
   ```

   Keep every other key already in the file.

5. **Confirm** to the user, in one line each, which model the attacker and the
   verifier will now use, and remind them that effort and probe counts are in
   `/config`. Mention that `main coding agent` follows whatever they pick in
   `/model`.
