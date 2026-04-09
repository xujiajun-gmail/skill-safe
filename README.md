# skill-safe

`skill-safe` is a CLI-first security scanner for third-party skills. It ingests a local skill directory or archive, normalizes it into a `Skill IR`, runs high-value static and semantic checks, and emits evidence-backed reports in text, JSON, or SARIF.

## What v0.1 does

- Ingests local directories, local git working trees, and zip/tar archives
- Detects risky execution chains, prompt-injection language, persistence patterns, secrets access, hook/startup entrypoints, and network targets
- Scores results across malice likelihood, exploitability, blast radius, privilege excess, and supply-chain trust
- Emits text, JSON, or SARIF reports for CI and manual review
- Provides a safe `--dynamic` observation mode that **does not execute untrusted code on the host**

## Install

```bash
python3 -m pip install -e .
```

## Usage

```bash
skill-safe scan /path/to/skill
skill-safe scan ./skill.zip --format json --output report.json
skill-safe scan ./risky-skill --format sarif --output report.sarif --dynamic
```

## Example JSON fields

- `summary.finding_count`
- `scores.overall`
- `scores.malice_likelihood`
- `findings[].evidence[]`
- `artifacts.permission_hints`
- `sandbox_observations.mode`

## Current limitations

- v0.1 is intentionally offline and local-input only; it does not fetch remote git or registry packages.
- Dynamic mode is a simulation/observation mode, not a hardened execution sandbox.
- YAML parsing is not implemented in v0.1; JSON and TOML manifests are parsed structurally, other text files are scanned heuristically.
- Semantic review is heuristic and evidence-backed; it is not an autonomous malware classifier.

## Development

```bash
python3 -m unittest discover -s tests
python3 -m skill_safe.cli scan tests/fixtures/risky_skill --format text --dynamic
```
