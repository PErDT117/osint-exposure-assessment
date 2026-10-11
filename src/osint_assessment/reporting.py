from __future__ import annotations

from typing import Any, Dict, List


def summarize(report: Dict[str, Any]) -> str:
    summary = report.get("executive_summary", {})
    return (
        f"Case {summary.get('case_id', 'UNKNOWN')} for {summary.get('org_name', 'UNKNOWN')} has "
        f"{summary.get('finding_count', 0)} findings across {summary.get('asset_count', 0)} in-scope assets."
    )


def build_recommendations_from_report(report: Dict[str, Any]) -> List[str]:
    recommendations = report.get("recommendations", [])
    return [r.get("title", "General review") for r in recommendations]
