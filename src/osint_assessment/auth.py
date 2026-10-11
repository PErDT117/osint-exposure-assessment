from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class AuthorizationRecord:
    ref: str
    org: str
    authority: str
    issued_at: datetime
    expires_at: datetime
    scope: str
    domains: List[str]
    repositories: List[str]
    allowed_sources: List[str]
    retention_days: int
    stop_conditions: List[str]
    notes: str = ""

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "AuthorizationRecord":
        return cls(
            ref=str(payload["ref"]),
            org=str(payload["org"]),
            authority=str(payload["authority"]),
            issued_at=datetime.fromisoformat(str(payload["issued_at"])),
            expires_at=datetime.fromisoformat(str(payload["expires_at"])),
            scope=str(payload["scope"]),
            domains=[str(item).strip() for item in payload.get("domains", [])],
            repositories=[str(item).strip() for item in payload.get("repositories", [])],
            allowed_sources=[str(item).strip() for item in payload.get("allowed_sources", [])],
            retention_days=int(payload.get("retention_days", 30)),
            stop_conditions=[str(item).strip() for item in payload.get("stop_conditions", [])],
            notes=str(payload.get("notes", "")),
        )

    def is_active(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.issued_at <= now <= self.expires_at

    def scope_covers_asset(self, asset: str) -> bool:
        normalized = asset.strip().lower()
        domain_match = any(normalized == d.lower() or normalized.startswith(f"{d.lower()}.") for d in self.domains)
        repo_match = any(normalized == r.lower() for r in self.repositories)
        return domain_match or repo_match


class ScopeRequiredError(RuntimeError):
    pass


@dataclass
class CaseRecord:
    case_id: str
    org_name: str
    authorization: Optional[AuthorizationRecord]
    domains: List[str]
    repositories: List[str]
    allowed_sources: List[str]
    collection_window: Dict[str, str]
    retention_days: int
    stop_conditions: List[str]
    notes: str = ""

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "CaseRecord":
        authorization = None
        if payload.get("authorization"):
            authorization = AuthorizationRecord.from_dict(payload["authorization"])

        return cls(
            case_id=str(payload["case_id"]),
            org_name=str(payload["org_name"]),
            authorization=authorization,
            domains=[str(item).strip() for item in payload.get("domains", [])],
            repositories=[str(item).strip() for item in payload.get("repositories", [])],
            allowed_sources=[str(item).strip() for item in payload.get("allowed_sources", [])],
            collection_window=dict(payload.get("collection_window", {})),
            retention_days=int(payload.get("retention_days", 30)),
            stop_conditions=[str(item).strip() for item in payload.get("stop_conditions", [])],
            notes=str(payload.get("notes", "")),
        )

    @classmethod
    def from_json(cls, path: str) -> "CaseRecord":
        import json

        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return cls.from_dict(payload)

    @property
    def is_in_scope(self) -> bool:
        if not self.authorization:
            return False
        if not self.domains and not self.repositories:
            return False
        return any(self.authorization.scope_covers_asset(asset) for asset in self.all_assets())

    def all_assets(self) -> List[str]:
        return list(dict.fromkeys(self.domains + self.repositories))


def ensure_collection_allowed(case: CaseRecord) -> None:
    if case.authorization is None:
        raise ScopeRequiredError("SCOPE_REQUIRED: authorization record is missing")

    now = datetime.now(timezone.utc)
    if not case.authorization.is_active(now):
        raise ScopeRequiredError(
            f"SCOPE_REQUIRED: authorization {case.authorization.ref} is expired or not yet valid"
        )

    if not case.is_in_scope:
        raise ScopeRequiredError("SCOPE_REQUIRED: asset is outside the authorized scope")
