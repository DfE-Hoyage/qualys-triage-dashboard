import csv
import os
from typing import Any, Dict, List, Optional

DEFAULT_CSV_PATH = os.path.join("data", "qualys_vulnerabilities.csv")


def _safe_int(value: Optional[str], default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def load_vulnerabilities(csv_path: str = DEFAULT_CSV_PATH) -> List[Dict[str, Any]]:
    """Load and normalise Qualys vulnerability findings from CSV."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Qualys dataset not found at: {csv_path}")

    records: List[Dict[str, Any]] = []
    with open(csv_path, mode="r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            cleaned = {k.strip(): (v.strip() if v is not None else "") for k, v in row.items() if k}
            cleaned["id"] = idx
            cleaned["QDS_num"] = _safe_int(cleaned.get("QDS"))
            cleaned["ARS_num"] = _safe_int(cleaned.get("ARS"))
            records.append(cleaned)

    return records


def calculate_kpis(records: List[Dict[str, Any]]) -> Dict[str, int]:
    """Aggregate executive summary metrics by QDS Level and remediation status."""
    kpis = {
        "total": len(records),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "active_unpatched": 0,
        "fixed": 0,
    }
    for row in records:
        level = row.get("QDS Level", "").lower()
        if level in ("critical", "high", "medium", "low"):
            kpis[level] += 1

        status = row.get("Vuln Status", "").lower()
        if status == "fixed":
            kpis["fixed"] += 1
        elif status in ("new", "active", "re-opened"):
            kpis["active_unpatched"] += 1

    return kpis


def filter_vulnerabilities(
    records: List[Dict[str, Any]],
    query: str = "",
    qds_level: str = "",
    status: str = "",
    service_offering: str = "",
    os_name: str = "",
) -> List[Dict[str, Any]]:
    """Filter vulnerability records using case-insensitive keyword search and multi-criteria dropdowns."""
    q = query.strip().lower()
    level_f = qds_level.strip().lower()
    status_f = status.strip().lower()
    service_f = service_offering.strip().lower()
    os_f = os_name.strip().lower()

    results: List[Dict[str, Any]] = []
    for row in records:
        if level_f and row.get("QDS Level", "").lower() != level_f:
            continue
        if status_f and row.get("Vuln Status", "").lower() != status_f:
            continue
        if service_f and row.get("Service Offering", "").lower() != service_f:
            continue
        if os_f and row.get("OS", "").lower() != os_f:
            continue

        if q:
            searchable = " ".join([
                row.get("QID", ""),
                row.get("CVE ID", ""),
                row.get("Vulnerability Name", ""),
                row.get("Server Name", ""),
                row.get("Private IP", ""),
                row.get("Category", ""),
            ]).lower()
            if q not in searchable:
                continue

        results.append(row)

    return results


def get_filter_options(records: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Extract sorted unique values for UI filter dropdowns."""
    severity_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4}
    qds_levels = sorted(
        {r["QDS Level"] for r in records if r.get("QDS Level")},
        key=lambda x: severity_order.get(x, 99),
    )
    return {
        "qds_levels": qds_levels,
        "statuses": sorted({r["Vuln Status"] for r in records if r.get("Vuln Status")}),
        "service_offerings": sorted({r["Service Offering"] for r in records if r.get("Service Offering")}),
        "operating_systems": sorted({r["OS"] for r in records if r.get("OS")}),
    }


def get_vulnerability_by_id(records: List[Dict[str, Any]], vuln_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve a single vulnerability finding by its row ID."""
    for row in records:
        if row.get("id") == vuln_id:
            return row
    return None
