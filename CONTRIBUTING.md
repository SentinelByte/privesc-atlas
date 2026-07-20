# Contributing to Privilege Escalation Atlas

Thank you for contributing. This guide covers the mechanics of adding or improving a technique entry, writing detection rules, and keeping the CI green.

---

## Ground rules

- All PoC scripts **must** require explicit authorization. Shell scripts that can cause harm should gate on a `--i-have-authorization` flag (see `techniques/macos/launch-agents/poc_reverse_shell.sh`).
- No hardcoded IP addresses, credentials, or command-line payloads. Use CLI arguments with safe defaults.
- READMEs are **generated artifacts** — edit `technique.yaml`, then run `atlas render`. Never edit `README.md` directly; CI will reject it.
- Every new technique must pass `atlas validate` before opening a PR.

---

## Adding a technique

### 1. Create the directory

```
techniques/<platform>/<technique-id>/
```

Platform is one of: `linux`, `macos`, `windows`, `ai-agent`.  
`technique-id` must be lowercase kebab-case and match the `id:` field in `technique.yaml`.

### 2. Write `technique.yaml`

The schema is defined in [`src/atlas/models.py`](src/atlas/models.py). Required fields:

```yaml
id: my-technique                 # kebab-case, matches folder name
title: Human-Readable Title
platform: linux                  # linux | macos | windows | ai-agent
category: misconfiguration       # free-form category label
severity: high                   # low | medium | high | critical
summary: >-
  One-sentence description (max 200 characters).
description: >-
  Extended explanation of the vulnerability and its mechanism.
mitre_attack:
  - technique_id: T1548.003
    name: 'Abuse Elevation Control Mechanism: Sudo and Sudo Caching'
requirements:
  - 'What the attacker needs to exploit this technique.'
exploitation_steps:
  - 'Step 1: what to do first.'
  - 'Step 2: what to do next.'
poc:
  - poc.sh                       # relative path; file must exist
detections:
  - type: sigma
    path: detections/sigma/my_technique.yml
    description: What this rule detects.
mitigations:
  - 'How to prevent or reduce the risk.'
references:
  - title: Reference Title
    url: https://example.com
disclaimer: >-
  For authorized security testing only.
```

YAML tip: any value that contains a colon followed by a space (`key: value`) must be quoted.

### 3. Add PoC scripts

- Keep defaults safe (e.g. `PAYLOAD="/usr/bin/whoami"` not a reverse shell).
- Override via CLI args, never hardcoded values.
- Use `set -euo pipefail` in bash scripts.
- Document cleanup steps inline.

### 4. Add detection rules

Place Sigma rules under `detections/sigma/` and osquery configs under `detections/osquery/`. Sigma rules are validated by `atlas validate` via pySigma — unsupported modifiers (e.g. `not_contains`) will fail. Use filter conditions instead:

```yaml
detection:
  selection:
    Field|contains: 'value'
  filter_exclude:
    Field|contains: '"'
  condition: selection and not filter_exclude
```

### 5. Validate and render

```bash
atlas validate      # must exit 0
atlas render        # writes README.md
```

Commit both `technique.yaml` and the generated `README.md`.

---

## Improving an existing technique

Edit `technique.yaml`, then re-run `atlas render`. Do not edit `README.md` directly.

---

## Running the test suite locally

```bash
pip install -e ".[dev]"
pytest
ruff check src/ tests/
mypy src/
```

CI runs the same checks on every push and PR.

---

## Detection rules without existing platform backends

If you're writing a Sigma rule for an unusual log source (e.g. AI agent audit logs), use a descriptive `definition` field in the `logsource` block and document the expected log format in the rule's `description`.

---

## Questions?

Open an issue or start a discussion. Please include the output of `atlas validate` if reporting a data problem.
