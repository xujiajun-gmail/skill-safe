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
- Includes a lightweight web app + REST API for uploading a skill directory/archive or scanning a remote URL

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

## Web app

Run the REST service and browser UI locally:

```bash
python3 -m app.service --host 127.0.0.1 --port 8000
```

Then open:

```text
http://127.0.0.1:8000
```

Available REST endpoints:

- `GET /api/v1/health`
- `POST /api/v1/scan/path` with JSON `{ "path": "...", "lang": "auto|zh|en", "dynamic": false }`
- `POST /api/v1/scan/url` with JSON `{ "url": "...", "lang": "auto|zh|en", "dynamic": false }`
- `POST /api/v1/scan/upload` with `multipart/form-data`
  - archive mode: fields `input_mode=archive`, `lang`, `dynamic`, file field `archive`
  - directory mode: fields `input_mode=directory`, `lang`, `dynamic`, repeated file field `files` using relative filenames

Notes:

- The UI is decoupled from the scanner service and calls the REST API via `fetch`.
- URL scans currently accept `http` / `https` only.
- Downloaded remote content is capped at 50 MB by default.

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

- The scanner still does not fetch remote git repositories or registry packages; web mode only supports direct `http` / `https` skill URLs.
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
python3 -m app.service --host 127.0.0.1 --port 8000
```
