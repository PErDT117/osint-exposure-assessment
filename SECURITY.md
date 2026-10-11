# Security policy

This project is intentionally constrained to safe, defensive, and human-reviewed privacy-preserving workflows.

## Prohibited use

The project must not be used to:

- investigate private individuals or infer personal identity
- identify or locate people
- link phone numbers, accounts, or online handle information to a person
- collect family, relationship, or personal history details
- engage in custody disputes, harassment, or surveillance
- perform active scanning, exploitation, credential testing, or login attempts
- access dark-web or stolen-data sources
- contact third parties without an explicit authorized human workflow

## Required controls

- Authorization is mandatory before any collection activity
- All collection must be passive and in-scope
- Source provenance and uncertainty must be preserved
- Evidence must be redacted before storage or reporting
- Secret values must never be stored, displayed, or tested
- All recommendations are prepared for a human security owner to review and execute
- Missing or stale data is not proof of absence

## Scope gate

If authorization is missing, expired, or does not cover the requested asset, the system must stop and return a `SCOPE_REQUIRED` outcome.

## Reporting

Findings must include:

- unique ID
- exact asset
- authorization reference and expiry
- source URL
- collection and validation time
- evidence type
- redacted locator
- confidence rationale
- freshness and corroboration details
- limitations
- recommended owner
- human-verified closure status

## Human in the loop

This system prepares findings for an authorized human to review. It does not automatically modify accounts, revoke credentials, block traffic, or contact service providers.
