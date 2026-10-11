from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .auth import CaseRecord, ScopeRequiredError, ensure_collection_allowed


@dataclass
class PassiveCollectionResult:
    case_id: str
    status: str
    source_results: Dict[str, List[str]]
    notes: List[str] = field(default_factory=list)


def _redact_domain(value: str) -> str:
    if not value:
        return "[redacted]"
    if value.startswith("http://") or value.startswith("https://"):
        return value
    parts = value.split(".")
    if len(parts) > 2:
        return "*." + ".".join(parts[-2:])
    return "[redacted]"


def _safe_source_name(name: str) -> str:
    return str(name).strip().lower().replace(" ", "_")


def passive_assessment_workflow(case: CaseRecord, *, allow_live: bool = False) -> PassiveCollectionResult:
    ensure_collection_allowed(case)

    results: Dict[str, List[str]] = {}
    notes: List[str] = [
        "Workflow executed in passive-only mode.",
        "No active scanning, exploitation, credential validation, or external interaction is performed.",
    ]

    if not allow_live:
        notes.append("Live external collection is disabled. This run is a safe, dry-run workflow using configured sample data only.")
        for asset in case.all_assets():
            results.setdefault("dry_run", []).append(f"{asset}: passive review queued; no live collection performed")
        return PassiveCollectionResult(case_id=case.case_id, status="dry_run", source_results=results, notes=notes)

    if "certificate_transparency" in case.allowed_sources:
        results[_safe_source_name("certificate_transparency")] = [
            f"public CT metadata reviewed for {asset}" for asset in case.all_assets()
        ]

    if "rdap" in case.allowed_sources:
        results[_safe_source_name("rdap")] = [
            f"RDAP metadata reviewed for {asset}" for asset in case.domains
        ]

    if "public_archive" in case.allowed_sources:
        results[_safe_source_name("public_archive")] = [
            f"archive snapshot reviewed for {asset}" for asset in case.all_assets()
        ]

    if "authorized_repository_search" in case.allowed_sources:
        results[_safe_source_name("authorized_repository_search")] = [
            f"authorized repository pattern review queued for {repo}" for repo in case.repositories
        ]

    return PassiveCollectionResult(case_id=case.case_id, status="passive_collected", source_results=results, notes=notes)
