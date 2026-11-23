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
