from __future__ import annotations

from typing import Any, Dict, List

from .auth import CaseRecord
from .models import Finding


def build_summary(case: CaseRecord, findings: List[Finding]) -> Dict[str, Any]:
    open_count = sum(1 for finding in findings if finding.closure_status.upper() != "CLOSED")
    return {
        "case_id": case.case_id,
        "org_name": case.org_name,
        "authorized_assets": case.all_assets(),
        "finding_count": len(findings),
        "open_findings": open_count,
        "authorized_sources": case.allowed_sources,
        "retention_days": case.retention_days,
        "stop_conditions": case.stop_conditions,
        "reporting_note": "This report is based only on passive, in-scope, and redacted evidence. Missing results are not proof of absence.",
    }


def build_recommendation_list(case: CaseRecord, findings: List[Finding]) -> List[str]:
    recommendations = [
        "Validate the authorization and expiry before any data collection is attempted.",
        "Restrict collection to the exact approved domains and repositories listed in the case record.",
        "Review source provenance and freshness for each finding before human escalation.",
        "Redact and preserve sensitive evidence, and ensure retention follows the approved policy.",
        "Assign each finding to a named human owner and require human verification before closure.",
    ]
    if findings:
        recommendations.insert(0, "Prioritize review of findings with the highest confidence and strongest corroboration.")
    return recommendations
