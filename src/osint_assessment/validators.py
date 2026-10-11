from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

ALLOWED_SOURCE_FAMILIES = {
    "certificate_transparency",
    "rdap",
    "public_archive",
    "authorized_repository_search",
    "hibp_domain",
    "dns_public",
    "web_metadata",
}


@dataclass
class ValidationIssue:
    code: str
    message: str


@dataclass
class ValidationResult:
    valid: bool
    issues: List[ValidationIssue] = field(default_factory=list)


def _normalize_asset(asset: str) -> str:
    return asset.strip().lower()


def validate_case(case: Any) -> ValidationResult:
    issues: List[ValidationIssue] = []

    if not case.case_id or not str(case.case_id).strip():
        issues.append(ValidationIssue("CASE_ID_REQUIRED", "case_id is required"))

    if not case.org_name or not str(case.org_name).strip():
        issues.append(ValidationIssue("ORG_NAME_REQUIRED", "org_name is required"))

    if case.authorization is None:
        issues.append(ValidationIssue("AUTH_REQUIRED", "authorization record is required"))
    else:
        if case.authorization.ref is None or not str(case.authorization.ref).strip():
            issues.append(ValidationIssue("AUTH_REF_REQUIRED", "authorization.ref is required"))
        if case.authorization.expires_at <= case.authorization.issued_at:
            issues.append(ValidationIssue("AUTH_INVALID_WINDOW", "authorization validity window is invalid"))
        if not case.authorization.domains and not case.authorization.repositories:
            issues.append(ValidationIssue("AUTH_NO_ASSETS", "authorization must list at least one domain or repository"))

    if not case.domains and not case.repositories:
        issues.append(ValidationIssue("NO_ASSETS", "case must include at least one in-scope domain or repository"))

    for asset in case.domains + case.repositories:
        normalized = _normalize_asset(asset)
        if "." not in normalized and "/" not in normalized:
            issues.append(ValidationIssue("INVALID_ASSET", f"asset does not resemble a domain or repository: {asset}"))

    if not case.allowed_sources:
        issues.append(ValidationIssue("NO_ALLOWED_SOURCES", "at least one allowed source is required"))

    for source in case.allowed_sources:
        if source.lower() not in ALLOWED_SOURCE_FAMILIES:
            issues.append(ValidationIssue("UNSAFE_SOURCE", f"source not in the approved passive source registry: {source}"))

    if case.retention_days <= 0:
        issues.append(ValidationIssue("INVALID_RETENTION", "retention_days must be positive"))

    start = case.collection_window.get("start")
    end = case.collection_window.get("end")
    if start and end:
        try:
            start_dt = datetime.fromisoformat(str(start))
            end_dt = datetime.fromisoformat(str(end))
            if start_dt >= end_dt:
                issues.append(ValidationIssue("INVALID_WINDOW", "collection_window.start must be before collection_window.end"))
        except ValueError:
            issues.append(ValidationIssue("INVALID_WINDOW_FORMAT", "collection_window timestamps must be ISO-8601"))

    return ValidationResult(valid=not issues, issues=issues)


def validate_finding(finding: Any) -> ValidationResult:
    issues: List[ValidationIssue] = []

    required_fields = [
        "finding_id",
        "case_id",
        "asset",
        "authorization_ref",
        "auth_expiry",
        "source_url",
        "collected_at",
        "check_time",
        "evidence_type",
        "redacted_locator",
        "confidence_rationale",
        "freshness_days",
        "recommended_owner",
    ]

    for field_name in required_fields:
        value = getattr(finding, field_name, None)
        if value is None or (isinstance(value, str) and not value.strip()):
            issues.append(ValidationIssue("REQUIRED_FIELD", f"{field_name} is required"))

    if getattr(finding, "freshness_days", -1) < 0:
        issues.append(ValidationIssue("INVALID_FRESHNESS", "freshness_days cannot be negative"))

    if getattr(finding, "confidence_rationale", "").strip() == "":
        issues.append(ValidationIssue("MISSING_CONFIDENCE", "confidence rationale is required"))

    return ValidationResult(valid=not issues, issues=issues)
