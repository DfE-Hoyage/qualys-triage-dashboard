import csv
import ipaddress
import os

CSV_PATH = os.path.join("data", "qualys_vulnerabilities.csv")

REAL_QUALYS_HEADERS = [
    "Service Type", "Service Offering", "Private IP", "Public IP",
    "PowerState", "DNS Name", "Server Name", "QID", "QDS Level",
    "Vulnerability Name", "ARS Level", "Last Detected", "QDS", "ARS",
    "Vuln Status", "FQDN", "SSL", "Port", "Protocol", "CVE ID",
    "Vendor Reference", "Solution", "Results", "Type", "OS", "Category"
]


def test_csv_exists_and_matches_production_schema():
    assert os.path.exists(CSV_PATH), "Anonymised Qualys CSV file is missing"
    with open(CSV_PATH, mode="r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == REAL_QUALYS_HEADERS, (
            f"Header mismatch. Expected {REAL_QUALYS_HEADERS}, got {reader.fieldnames}"
        )
        rows = list(reader)
        assert len(rows) >= 50, "Expected at least 50 synthetic vulnerability records"


def test_csv_ips_are_strictly_anonymised():
    """SEC-01: Ensure Private IP and Public IP only contain RFC 5737 documentation IPs or N/A."""
    doc_nets = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]
    with open(CSV_PATH, mode="r", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            for col in ("Private IP", "Public IP"):
                val = row[col].strip()
                if val and val.upper() not in ("N/A", "NONE", "-"):
                    ip_obj = ipaddress.ip_address(val)
                    assert any(ip_obj in net for net in doc_nets), (
                        f"Non-anonymised IP in {col}: {ip_obj}"
                    )
from services.vuln_service import (
    load_vulnerabilities,
    calculate_kpis,
    filter_vulnerabilities,
    get_filter_options,
    get_vulnerability_by_id,
)


def test_load_vulnerabilities_returns_structured_records():
    records = load_vulnerabilities(CSV_PATH)
    assert len(records) == 120
    first = records[0]
    assert "id" in first
    assert first["QID"] == "37667"
    assert first["CVE ID"] == "CVE-2021-44228"
    assert first["QDS Level"] == "Critical"
    assert isinstance(first["QDS_num"], int)
    assert isinstance(first["ARS_num"], int)


def test_calculate_kpis_counts_severities_and_active():
    records = load_vulnerabilities(CSV_PATH)
    kpis = calculate_kpis(records)
    assert kpis["total"] == 120
    assert kpis["critical"] == 30
    assert kpis["high"] == 30
    assert kpis["medium"] == 30
    assert kpis["low"] == 30
    assert kpis["active_unpatched"] == 90  # New (30) + Active (30) + Re-Opened (30)


def test_filter_vulnerabilities_by_keyword_and_criteria():
    records = load_vulnerabilities(CSV_PATH)

    # Keyword search across CVE / Name / Host
    cve_matches = filter_vulnerabilities(records, query="CVE-2021-44228")
    assert len(cve_matches) >= 1
    assert all("CVE-2021-44228" in r["CVE ID"] for r in cve_matches)

    # Multi-criteria filter (QDS Level + Vuln Status + Service Offering)
    filtered = filter_vulnerabilities(
        records,
        qds_level="Critical",
        status="New",
        service_offering="Corporate Web",
    )
    assert len(filtered) > 0
    assert all(
        r["QDS Level"] == "Critical"
        and r["Vuln Status"] == "New"
        and r["Service Offering"] == "Corporate Web"
        for r in filtered
    )


def test_get_filter_options_and_single_record_lookup():
    records = load_vulnerabilities(CSV_PATH)
    options = get_filter_options(records)
    assert "Critical" in options["qds_levels"]
    assert "Corporate Web" in options["service_offerings"]
    assert "New" in options["statuses"]

    item = get_vulnerability_by_id(records, 1)
    assert item is not None
    assert item["id"] == 1
    assert get_vulnerability_by_id(records, 99999) is None
