from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


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
    def new(cls, case_id: str, idx: int, **kwargs) -> "Finding":
        default_id = f"F-{case_id}-{idx:04d}"
        return cls(finding_id=kwargs.pop("finding_id", default_id), case_id=case_id, **kwargs)

    def to_dict(self) -> dict:
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
