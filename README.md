# osint-exposure-assessment

A privacy-preserving, authorization-first OSINT exposure-assessment system for organizations that own or are explicitly authorized to assess specified domains and public code repositories.

This project implements a defensive, passive-only workflow designed for authorized security reviews. It is intentionally limited to public metadata, redacted evidence, and human-reviewed remediation. It never performs active scanning, credential testing, exploitation, or external account interaction.

## What this project now includes

- Authorization, scope, and retention validation
- Rich case validation and source gating
- Five role-driven workflow stages
- Passive source registry for public metadata gathering
- Redacted finding schema and evidence provenance
- Full report generation with prioritized recommendations
- Synthetic sample data and comprehensive tests

## Architecture

- `auth.py`: authorization records and scope enforcement
- `validators.py`: case validation rules and source policy checks
- `sources.py`: passive source registry and mock/live orchestration helpers
- `collectors.py`: passive collection workflow orchestration
- `models.py`: finding and evidence models
- `reporting.py`: final evidence-backed report generation
- `cli.py`: CLI entry point for dry-run or authorized passive review
- `sample_data/`: fictional example data only
- `tests/`: validation and reporting tests

## Safety and compliance posture

This project is intentionally constrained to safe, defensive, and human-reviewed privacy-preserving workflows.

- Passive-only collection only
- No active probes, brute forcing, login attempts, or credential testing
- No secret validation or external verification of credentials
- No dark-web or stolen-data access
- No contacting people, service providers, or third parties
- No automatic revocation or blocking
- Findings are redacted, evidence-backed, and human-review required

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=src
pytest -q
```

## Example usage

```bash
python -m osint_assessment.cli --sample --format json
```

This runs a synthetic, non-live assessment using sample data only.

To perform a live passive workflow, you must explicitly provide a valid case record with authorization in force and a `--allow-live` flag under a controlled, written scope grant. The default path remains dry-run for safety.

## License

MIT
