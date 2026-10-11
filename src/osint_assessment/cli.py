from __future__ import annotations

import argparse
import json

from .auth import CaseRecord, ScopeRequiredError, ensure_collection_allowed
from .collectors import generate_findings
from .reporting import generate_report


def _load_case(path: str) -> CaseRecord:
    return CaseRecord.from_json(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Passive, authorization-first exposure assessment report generator")
    parser.add_argument("--case", required=True, help="Path to a JSON case definition")
    parser.add_argument("--sample", action="store_true", help="Use synthetic sample execution and do not perform any live collection")
    parser.add_argument("--allow-live", action="store_true", help="Only allow live passive collection if the case authorization is valid and scope approved")
    parser.add_argument("--format", choices=["json", "pretty"], default="json")
    args = parser.parse_args()

    case = _load_case(args.case)

    try:
        ensure_collection_allowed(case)
    except ScopeRequiredError:
        print("SCOPE_REQUIRED: authorization missing, expired, or outside approved scope")
        raise SystemExit(2)

    findings = generate_findings(case)
    report = generate_report(case, findings)

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        lines = [
            f"Case: {report['case_id']} | Org: {report['org_name']}",
            f"Findings: {report['executive_summary']['finding_count']}",
            "",
        ]
        for finding in report["findings"]:
            lines.append(f"- {finding['finding_id']}: {finding['asset']} ({finding['evidence_type']})")
        print("\n".join(lines))


if __name__ == "__main__":
    main()
