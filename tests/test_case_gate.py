import json
from datetime import datetime

from osint_assessment.auth import CaseRecord, ScopeRequiredError, ensure_collection_allowed
from osint_assessment.collectors import generate_findings
from osint_assessment.reporting import generate_report
from osint_assessment.validators import validate_case


def test_case_is_rejected_without_authorization():
    case = CaseRecord(
        case_id="CASE-001",
        org_name="Example Org",
        authorization=None,
        domains=["example.org"],
        repositories=[],
        allowed_sources=["rdap"],
        collection_window={"start": "2026-01-01T00:00:00+00:00", "end": "2026-01-31T00:00:00+00:00"},
        retention_days=30,
        stop_conditions=["authorization missing"],
    )

    try:
        ensure_collection_allowed(case)
        raise AssertionError("Expected ScopeRequiredError")
    except ScopeRequiredError:
        pass


def test_rich_case_validation_flags_invalid_sources():
    case = CaseRecord(
        case_id="CASE-001",
        org_name="Example Org",
        authorization=None,
        domains=["example.org"],
        repositories=[],
        allowed_sources=["nmap"],
        collection_window={"start": "2026-01-01T00:00:00+00:00", "end": "2026-01-31T00:00:00+00:00"},
        retention_days=30,
        stop_conditions=["authorization missing"],
    )

    result = validate_case(case)
    assert result.valid is False
    assert any(issue.code == "AUTH_REQUIRED" for issue in result.issues)
    assert any(issue.code == "UNSAFE_SOURCE" for issue in result.issues)


def test_report_generation_uses_redacted_finding_fields():
    with open("sample_data/case_record.json", "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    case = CaseRecord.from_dict(payload)
    findings = generate_findings(case)
    report = generate_report(case, findings)

    assert report["case_id"] == "CASE-ORG-001"
    assert len(report["findings"]) >= 1
    assert report["findings"][0]["redacted_locator"]
    assert report["executive_summary"]["finding_count"] == len(findings)


def test_authorized_case_is_allowed():
    from osint_assessment.auth import AuthorizationRecord

    auth = AuthorizationRecord(
        ref="AUTH-001",
        org="Example Org",
        authority="CISO",
        issued_at=datetime(2026, 1, 1),
        expires_at=datetime(2027, 1, 1),
        scope="Assess approved domains and repositories only.",
        domains=["example.org"],
        repositories=["ExampleOrg/public-docs"],
        allowed_sources=["rdap"],
        retention_days=90,
        stop_conditions=["authorization missing"],
    )

    case = CaseRecord(
        case_id="CASE-001",
        org_name="Example Org",
        authorization=auth,
        domains=["example.org"],
        repositories=["ExampleOrg/public-docs"],
        allowed_sources=["rdap"],
        collection_window={"start": "2026-01-01T00:00:00+00:00", "end": "2026-01-31T00:00:00+00:00"},
        retention_days=90,
        stop_conditions=["authorization missing"],
    )

    ensure_collection_allowed(case)
    assert case.is_in_scope is True
