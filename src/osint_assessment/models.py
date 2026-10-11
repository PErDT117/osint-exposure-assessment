from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .auth import CaseRecord
from .validators import passive_assessment_workflow


@dataclass
class EvidenceRecord:
    source_name: str
    source_url: str
    collected_at: datetime
    asset: str
    evidence_type: str
    redacted_locator: str
    confidence_rationale: str
    freshness_days: int
    corroboration: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


@dataclass
class Finding:
    finding_id: str
    case_id: str
    asset: str
    authorization_ref: str
    auth_expiry: str
    source_url: str
    collected_at: str
    check_time: str
    evidence_type: str
    redacted_locator: str
    confidence_rationale: str
    freshness_days: int
    corroboration: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    recommended_owner: str = "security-owner@example.com"
    human_verified: bool = False
    closure_status: str = "OPEN"

    @classmethod
    def from_evidence(cls, case: CaseRecord, evidence: EvidenceRecord, index: int) -> "Finding":
        return cls(
            finding_id=f"F-{case.case_id}-{index:04d}",
            case_id=case.case_id,
            asset=evidence.asset,
            authorization_ref=case.authorization.ref if case.authorization else "UNKNOWN",
            auth_expiry=(case.authorization.expires_at.isoformat() if case.authorization else "UNKNOWN"),
            source_url=evidence.source_url,
            collected_at=evidence.collected_at.isoformat(),
            check_time=datetime.now(timezone.utc).isoformat(),
            evidence_type=evidence.evidence_type,
            redacted_locator=evidence.redacted_locator,
            confidence_rationale=evidence.confidence_rationale,
            freshness_days=evidence.freshness_days,
            corroboration=evidence.corroboration,
            limitations=evidence.limitations,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "asset": self.asset,
            "authorization_ref": self.authorization_ref,
            "auth_expiry": self.auth_expiry,
            "source_url": self.source_url,
            "collected_at": self.collected_at,
            "check_time": self.check_time,
            "evidence_type": self.evidence_type,
            "redacted_locator": self.redacted_locator,
            "confidence_rationale": self.confidence_rationale,
            "freshness_days": self.freshness_days,
            "corroboration": self.corroboration,
            "limitations": self.limitations,
            "recommended_owner": self.recommended_owner,
            "human_verified": self.human_verified,
            "closure_status": self.closure_status,
        }


def build_default_evidence(case: CaseRecord) -> List[EvidenceRecord]:
    evidence: List[EvidenceRecord] = []
    for index, asset in enumerate(case.all_assets()):
        evidence.append(
            EvidenceRecord(
                source_name="passive_review",
                source_url=f"https://example.invalid/assessment/{case.case_id}/{asset}",
                collected_at=datetime.now(timezone.utc),
                asset=asset,
                evidence_type="public-metadata-review",
                redacted_locator=f"{asset.split('/')[0] if '/' in asset else asset} [redacted]",
                confidence_rationale="Passive metadata review only; evidence is non-authoritative and historical unless corroborated.",
                freshness_days=7,
                corroboration=["public metadata source", "authorization gate validated"],
                limitations=["not proof of active compromise", "historical or stale metadata may be incomplete"],
            )
        )
    return evidence


def generate_findings(case: CaseRecord) -> List[Finding]:
    passive_result = passive_assessment_workflow(case, allow_live=False)
    evidence = build_default_evidence(case)
    findings = [Finding.from_evidence(case, item, idx + 1) for idx, item in enumerate(evidence)]
    if not passive_result.source_results:
        return findings
    return findings
