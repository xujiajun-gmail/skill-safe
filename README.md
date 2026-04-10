# skill-safe

`skill-safe` is a CLI-first security scanner for third-party skills. It ingests a local skill directory or archive, normalizes it into a `Skill IR`, runs gatekeeper, alignment, and flow checks, and emits evidence-backed reports in text, JSON, or SARIF.

## What v0.2 does

- Ingests local directories, local git working trees, and zip/tar archives
- Detects risky execution chains, prompt-injection language, persistence patterns, secrets access, hook/startup entrypoints, network targets, destructive actions, credential leakage, workspace poisoning, and trust mismatches
- Supports taxonomy-aware `scan`, `diff`, and `explain` workflows
- Produces bilingual human-readable output in Chinese or English, with automatic language selection
- Builds minimal capability-graph / flow analysis for:
  - `CH-001` untrusted string -> shell
  - `CH-002` untrusted string -> context
  - `CH-003` untrusted string -> sensitive action parameter
  - `CH-004` secrets read -> external sink
- Includes configurable policy profiles, taxonomy overrides, and environment toggles via `skill-safe.yml`
- Carries optional LLM configuration scaffolding without making core admission depend on model calls
- Scores results across malice likelihood, exploitability, blast radius, privilege excess, and supply-chain trust
- Emits text, JSON, or SARIF reports for CI and manual review
- Provides a safe `--dynamic` observation mode that **does not execute untrusted code on the host**

## Install

### Activate the conda environment

If you have already created the environment from `environment.yml`, activate it before running the CLI:

```bash
conda activate skillsafe
```

If `conda activate` does not work in your shell yet, initialize conda for `zsh` and restart the shell:

```bash
conda init zsh
exec zsh
conda activate skillsafe
```

You can also run commands without activating the shell first:

```bash
conda run -n skillsafe skill-safe scan tests/fixtures/risky_skill --format text
```

### Install the project

```bash
python3 -m pip install -e .
```

## Usage

```bash
skill-safe scan /path/to/skill
skill-safe scan ./skill.zip --format json --output report.json
skill-safe scan ./risky-skill --format sarif --output report.sarif --dynamic
skill-safe diff ./old-skill ./new-skill --format json --output diff.json
skill-safe explain ./report.json --lang zh
```

## Example JSON fields

- `summary.finding_count`
- `scores.overall`
- `scores.malice_likelihood`
- `findings[].evidence[]`
- `findings[].taxonomy_id`
- `findings[].decision_hint`
- `flows[]`
- `flows[].source_node`
- `flows[].sink_node`
- `flows[].path_labels`
- `artifacts.permission_hints`
- `runtime_trace.mode`

## Current limitations

- v0.2 is intentionally offline and local-input only; it does not fetch remote git or registry packages.
- Dynamic mode is a simulation/observation mode, not a hardened execution sandbox.
- YAML config parsing is intentionally minimal in v0.2; common nested settings are supported, but this is not yet a full YAML implementation.
- Semantic review is heuristic and evidence-backed; it is not an autonomous malware classifier.
- Flow analysis is currently a minimal capability-graph layer focused on high-value chains; it is not yet a full multi-skill graph engine.

## Development

```bash
python3 -m unittest discover -s tests
python3 -m skill_safe.cli scan tests/fixtures/risky_skill --format text --dynamic
python3 -m skill_safe.cli diff tests/fixtures/diff_case_v1 tests/fixtures/diff_case_v2 --lang en
python3 -m skill_safe.cli explain /tmp/report.json --lang zh
```
