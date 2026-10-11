from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

from .auth import AuthorizationRecord, CaseRecord, ScopeRequiredError, ensure_collection_allowed


@dataclass
class AssessmentRoleResult:
    role_name: str
    status: str
    notes: List[str] = field(default_factory=list)


def passive_surface_inventory(case: CaseRecord) -> AssessmentRoleResult:
    ensure_collection_allowed(case)
    return AssessmentRoleResult(
        role_name="passive_surface_inventory",
        status="ready",
        notes=[
            "Allowed sources are limited to passive, public metadata sources.",
            "No active scanning or direct probing is permitted.",
            "Any observation is treated as partial and non-authoritative.",
        ],
    )


def repository_secret_review(case: CaseRecord) -> AssessmentRoleResult:
    ensure_collection_allowed(case)
    return AssessmentRoleResult(
        role_name="authorized_public_repository_secret_pattern_review",
        status="ready",
        notes=[
            "Repository review is restricted to exact authorized repositories only.",
            "Secret-scanning is pattern-oriented and non-validating.",
            "No credentials are tested or verified externally.",
        ],
    )


def breach_archive_review(case: CaseRecord) -> AssessmentRoleResult:
    ensure_collection_allowed(case)
    return AssessmentRoleResult(
        role_name="breach_archive_review",
        status="ready",
        notes=[
            "Use reputable breach disclosure and archive sources only.",
            "Domain ownership must be verified before domain-based HIBP checks.",
            "Archive findings are historical fragments, not proof of current compromise.",
        ],
    )


def correlation_analysis(case: CaseRecord) -> AssessmentRoleResult:
    ensure_collection_allowed(case)
    return AssessmentRoleResult(
        role_name="evidence_correlation_and_risk_analysis",
        status="ready",
        notes=[
            "Evidence is deduplicated by source, asset, and locator.",
            "Confidence, freshness, and corroboration are kept separate from business priority.",
            "A missing result is not proof that no exposure exists.",
        ],
    )


def remediation_recommendations(case: CaseRecord) -> AssessmentRoleResult:
    ensure_collection_allowed(case)
    return AssessmentRoleResult(
        role_name="remediation_recommendations",
        status="ready",
        notes=[
            "Recommendations are prepared for an authorized human owner.",
            "The system never automatically blocks traffic, revokes credentials, or contacts third parties.",
            "Actions are prioritized by evidence-backed business impact and human review ability.",
        ],
    )
