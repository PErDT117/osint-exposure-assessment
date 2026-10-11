# osint-exposure-assessment

A privacy-preserving, authorization-first OSINT exposure-assessment system for organizations that own or are explicitly authorized to assess specified domains and public code repositories.

This project intentionally implements a defensive, passive-only workflow with strong safety and audit controls. It does not perform active scanning, credential testing, exploitation, or any unauthorized investigation. It is designed to support a human security owner in reviewing public exposure risk through a controlled case record and redacted evidence trail.

## Project goals

- Enforce authorization before collection
- Restrict collection to passive, public, and in-scope sources
- Preserve source provenance and uncertainty
- Store only redacted evidence and safe metadata
- Prepare recommendations for an authorized human reviewer
- Avoid all prohibited uses, including surveillance, personal targeting, or active account interaction

## Safety policy

This project is for organizations to assess their own public exposure or exposure of authorized assets only. It is not for personal investigations, account-linking, surveillance, or harassment.

- No active scans or probes
- No exploitation, brute force, account testing, or login attempts
- No secret testing or validation
- No dark-web access or stolen-data access
- No contact with people, service providers, or third parties
- No automatic revocation, blocking, or account changes
- Redact sensitive evidence and never print or store secret values

## Current repository state

I inspected the repository before writing code. At this stage it contained only a minimal README, license, and gitignore, with no implementation files, no dependencies, no tests, and no application logic. The project was effectively a blank scaffold rather than an operational workflow.

## Minimal safe implementation

This repository now provides a minimal, safe Python implementation focused on:

1. Authorization gating
2. Case record management
3. Finding schema and provenance tracking
4. Role-based workflow stubs for passive assessment and evidence handling
5. Sample synthetic data that contains no real people, credentials, or targets
6. Tests covering allowed/blocked workflows

## Architecture

The system is organized around a single access-controlled case record that serves as the source of truth.

- `auth`: authorization validation and scope gates
- `models`: case record and finding schema
- `roles`: five workflow roles that define what the system is allowed to do
- `reporting`: human-readable risk summary and recommendations
- `sample_data`: fictional domain and repository examples only
- `tests`: enforcement of safety and authorization behaviors

## Roles

1. Passive surface inventory
2. Authorized public-repository secret-pattern review
3. Reputable breach-disclosure and web-archive metadata review
4. Evidence correlation and risk analysis
5. Remediation recommendations

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=src
pytest -q
```

## Sample data

The project includes fictional sample data only:

- `sample_data/case_record.json`
- `sample_data/findings.json`

These examples do not reference real people, real phone numbers, real credentials, or live targets.

## Example usage

```python
from osint_assessment.case import CaseRecord
from osint_assessment.auth import ScopeRequiredError, ensure_collection_allowed

case = CaseRecord.from_json("sample_data/case_record.json")
ensure_collection_allowed(case)
print(case.case_id)
```

## Security and governance considerations

- Authorization must be recorded and validated before collection starts
- Allowed sources, time windows, retention policy, and stop conditions are enforced
- Findings are redacted and provenance-aware
- Missing results are treated as incomplete information, not proof of absence
- Technical severity and business priority are separated from evidence confidence
- No automatic credential changes or external actions are performed

## License

MIT
