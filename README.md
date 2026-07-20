# Privilege Escalation Atlas

A schema-validated, CI-enforceable knowledge base of privilege escalation techniques across Linux, macOS, Windows, and AI agents.

Each technique entry is a single `technique.yaml` file — the source of truth. READMEs are generated artifacts. Detection rules, PoC scripts, and mitigations live alongside the data they describe.

[![CI](https://github.com/sentinelbyte/privesc-atlas/actions/workflows/ci.yml/badge.svg)](https://github.com/sentinelbyte/privesc-atlas/actions/workflows/ci.yml)

---

## Techniques

| ID | Platform | Severity | MITRE ATT&CK |
|----|----------|----------|--------------|
| [sudo-nopasswd](techniques/linux/sudo-nopasswd/) | linux | high | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) |
| [launch-agents](techniques/macos/launch-agents/) | macos | medium | [T1543.001](https://attack.mitre.org/techniques/T1543/001/) |
| [launch-daemon](techniques/macos/launch-daemon/) | macos | high | [T1543.004](https://attack.mitre.org/techniques/T1543/004/) |
| [unquoted-service-path](techniques/windows/unquoted-service-path/) | windows | high | [T1574.009](https://attack.mitre.org/techniques/T1574/009/) |
| [mcp-tool-poisoning](techniques/ai-agent/mcp-tool-poisoning/) | ai-agent | critical | [T1059](https://attack.mitre.org/techniques/T1059/) |

Run `atlas list` to see the live table directly from the data.

---

## Repository Structure

```
techniques/
  <platform>/
    <technique-id>/
      technique.yaml          ← schema-validated source of truth
      README.md               ← generated; do not edit by hand
      poc.sh / exploit.py     ← proof-of-concept
      poc/demo.py             ← (AI techniques) runnable demo
      detections/
        sigma/<rule>.yml      ← Sigma detection rule
        osquery/<rule>.conf   ← osquery scheduled query

src/atlas/
  models.py                   ← Pydantic schema for technique.yaml
  loader.py                   ← discovers and loads all techniques
  render.py                   ← Jinja2 README renderer
  sigma_lint.py               ← pySigma syntax validator
  policy.py                   ← AI agent least-privilege policy engine
  cli.py                      ← atlas CLI (validate / render / list / attack-layer)
  templates/technique.md.j2   ← README template

tests/                        ← pytest test suite (97% coverage)
.github/workflows/ci.yml      ← CI: lint + typecheck + test + validate + render --check
```

---

## atlas CLI

Install the package (editable mode for development):

```bash
pip install -e ".[dev]"
```

| Command | What it does |
|---------|-------------|
| `atlas validate` | Schema-validates every `technique.yaml` and Sigma-lints all detection rules. Exits non-zero on any failure — use as a CI gate. |
| `atlas render` | Regenerates `README.md` for each technique from its `technique.yaml`. |
| `atlas render --check` | Fails if any README is stale (CI gate). |
| `atlas list` | Prints a Rich table: ID, Platform, Severity, MITRE ATT&CK, Detections. |
| `atlas attack-layer` | Emits a MITRE ATT&CK Navigator layer JSON of covered techniques. |

---

## Architecture

The data flow is deliberately one-directional:

```
technique.yaml  →  atlas validate  →  atlas render  →  README.md
     ↓
atlas attack-layer  →  attack-navigator-layer.json
```

`technique.yaml` is the only file humans edit. Everything else is derived from it. CI enforces this by running `atlas render --check` — a PR that edits a README directly will fail.

---

## Adding a Technique

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. The short version:

1. Create `techniques/<platform>/<technique-id>/technique.yaml` following the schema in `src/atlas/models.py`.
2. Add PoC scripts and detection rules in the same directory.
3. Run `atlas validate` — fix any errors.
4. Run `atlas render` — this writes `README.md`.
5. Commit everything including the generated README.

---

## Development

```bash
pip install -e ".[dev]"
pytest                  # run the test suite
ruff check src/ tests/  # lint
mypy src/               # type check
bandit -r src/ -ll      # security scan
atlas validate          # validate all technique data
atlas render --check    # verify READMEs are current
```

---

## Purpose

- **Red teamers** — structured PoC scripts with explicit authorization guards.
- **Blue teamers** — detection rules (Sigma, osquery) alongside the technique they cover.
- **Security engineers** — machine-readable data for MITRE ATT&CK Navigator layers and tooling.
- **AI security researchers** — the MCP tool-poisoning entry and `policy.py` are a reference implementation of provenance-aware tool-call gating.

---

## License

[Apache 2.0](LICENSE) — SentinelByte
