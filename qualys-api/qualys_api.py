"""
qualys_api.py
=============
Wrapper around the Qualys VMDR API for pulling vulnerability scan results,
filtering by severity, and exporting prioritized CVE lists to CSV.

This is a stripped-down version of the automation I used to replace manual
Qualys report exports — it pulls the latest scan data, filters to critical/high
findings, and routes them to a CSV that feeds our Jira ticket automation.

Usage:
    python qualys_api.py --severity 4,5 --output vulnerabilities.csv
    python qualys_api.py --host 10.0.1.20 --severity 5
    python qualys_api.py --demo   (runs without API credentials)

Author: Apurva Tiwari
"""

import argparse
import csv
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime
from io import StringIO

QUALYS_BASE_URL = os.getenv("QUALYS_BASE_URL", "https://qualysapi.qualys.com")
QUALYS_USERNAME = os.getenv("QUALYS_USERNAME", "")
QUALYS_PASSWORD = os.getenv("QUALYS_PASSWORD", "")

SEVERITY_LABELS = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

SLA_DAYS = {5: 3, 4: 14, 3: 30, 2: 90, 1: 180}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Vulnerability:
    host_ip: str
    hostname: str
    cve_id: str
    qid: str                # Qualys vulnerability ID
    title: str
    severity: int
    severity_label: str
    cvss_base: float
    cvss_temporal: float
    patch_available: bool
    exploitable: bool
    first_detected: str
    last_detected: str
    sla_due_days: int
    remediation: str
    os: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Qualys API client
# ---------------------------------------------------------------------------

class QualysClient:

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url
        self.username = username
        self.password = password
        self._session = None
        self._connected = False
        self._connect()

    def _connect(self):
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            self._session = requests.Session()
            self._session.auth = HTTPBasicAuth(self.username, self.password)
            self._session.headers.update({
                "X-Requested-With": "SecurityAutomationToolkit",
                "Content-Type": "text/xml"
            })
            self._connected = bool(self.username and self.password)
            if not self._connected:
                print("[!] No credentials set — use QUALYS_USERNAME / QUALYS_PASSWORD env vars")
        except ImportError:
            print("[!] requests not installed: pip install requests")

    def get_host_detections(
        self,
        severity_filter: list[int] = None,
        host_ip: str = None,
        max_records: int = 500
    ) -> str:
        """
        Calls Qualys VMDR Host Detection API.
        Returns raw XML response string.
        """
        if not self._connected:
            return None

        params = {
            "action": "list",
            "show_results": 1,
            "output_format": "XML",
            "max_records": max_records,
            "status": "New,Active,Re-Opened",
        }
        if severity_filter:
            params["severities"] = ",".join(str(s) for s in severity_filter)
        if host_ip:
            params["ips"] = host_ip

        try:
            resp = self._session.get(
                f"{self.base_url}/api/2.0/fo/asset/host/vm/detection/",
                params=params,
                timeout=60
            )
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            print(f"[!] API error: {e}")
            return None


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------

def parse_detections_xml(xml_str: str) -> list[Vulnerability]:
    vulns = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        print(f"[!] XML parse error: {e}")
        return []

    for host in root.findall(".//HOST"):
        ip = host.findtext("IP", "")
        hostname = host.findtext("DNS", "") or host.findtext("NETBIOS", "") or ip
        os_name = host.findtext("OS", "")

        for detection in host.findall(".//DETECTION"):
            qid = detection.findtext("QID", "")
            severity = int(detection.findtext("SEVERITY", "0"))
            cvss_base = float(detection.findtext("CVSS_BASE", "0") or 0)
            cvss_temporal = float(detection.findtext("CVSS_TEMPORAL", "0") or 0)
            patch_available = detection.findtext("PATCH_AVAILABLE", "0") == "1"
            exploitable = detection.findtext("IS_EXPLOITABLE", "0") == "1"
            first_detected = detection.findtext("FIRST_FOUND_DATETIME", "")
            last_detected = detection.findtext("LAST_FOUND_DATETIME", "")

            # Pull CVEs from nested VULN_INFO
            cve_list = [
                cve.text for cve in detection.findall(".//CVE_ID")
                if cve.text
            ]
            cve_id = ", ".join(cve_list) if cve_list else "N/A"
            title = detection.findtext(".//TITLE", f"QID-{qid}")
            remediation = detection.findtext(".//SOLUTION", "See Qualys KB")

            vulns.append(Vulnerability(
                host_ip=ip,
                hostname=hostname,
                cve_id=cve_id,
                qid=qid,
                title=title,
                severity=severity,
                severity_label=SEVERITY_LABELS.get(severity, "Unknown"),
                cvss_base=cvss_base,
                cvss_temporal=cvss_temporal,
                patch_available=patch_available,
                exploitable=exploitable,
                first_detected=first_detected,
                last_detected=last_detected,
                sla_due_days=SLA_DAYS.get(severity, 180),
                remediation=remediation[:200],
                os=os_name
            ))

    return vulns


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_csv(vulns: list[Vulnerability], output_path: str):
    if not vulns:
        print("[!] No vulnerabilities to export.")
        return
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(vulns[0].to_dict().keys()))
        writer.writeheader()
        writer.writerows([v.to_dict() for v in vulns])
    print(f"[+] Exported {len(vulns)} vulnerabilities → {output_path}")


def print_summary(vulns: list[Vulnerability]):
    from collections import Counter
    print(f"\n{'='*55}")
    print(f" Qualys VMDR Summary — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*55}")
    print(f" Total findings : {len(vulns)}")
    counts = Counter(v.severity_label for v in vulns)
    for label in ["Critical", "High", "Medium", "Low"]:
        print(f"  {label:<14}: {counts.get(label, 0)}")
    print(f" Exploitable    : {sum(1 for v in vulns if v.exploitable)}")
    print(f" Patch available: {sum(1 for v in vulns if v.patch_available)}")

    print(f"\n Top 10 by CVSS score:")
    for v in sorted(vulns, key=lambda x: x.cvss_base, reverse=True)[:10]:
        exploit_flag = " [EXPLOITABLE]" if v.exploitable else ""
        print(f"  [{v.severity_label}] {v.host_ip} | {v.cve_id} | CVSS {v.cvss_base} | SLA {v.sla_due_days}d{exploit_flag}")
    print()


# ---------------------------------------------------------------------------
# Demo mode
# ---------------------------------------------------------------------------

DEMO_XML = """<?xml version="1.0" encoding="UTF-8"?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <HOST_LIST>
      <HOST>
        <IP>10.0.1.20</IP>
        <DNS>workstation-finance1</DNS>
        <OS>Windows 10 Enterprise</OS>
        <DETECTION_LIST>
          <DETECTION>
            <QID>91819</QID>
            <SEVERITY>5</SEVERITY>
            <CVSS_BASE>9.8</CVSS_BASE>
            <CVSS_TEMPORAL>8.5</CVSS_TEMPORAL>
            <IS_EXPLOITABLE>1</IS_EXPLOITABLE>
            <PATCH_AVAILABLE>1</PATCH_AVAILABLE>
            <FIRST_FOUND_DATETIME>2024-10-01T08:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2024-10-18T08:00:00Z</LAST_FOUND_DATETIME>
            <VULN_INFO>
              <TITLE>Microsoft Windows RCE Vulnerability</TITLE>
              <CVE_ID_LIST><CVE_ID>CVE-2024-21334</CVE_ID></CVE_ID_LIST>
              <SOLUTION>Apply Microsoft security update KB5034441</SOLUTION>
            </VULN_INFO>
          </DETECTION>
          <DETECTION>
            <QID>105881</QID>
            <SEVERITY>4</SEVERITY>
            <CVSS_BASE>7.5</CVSS_BASE>
            <CVSS_TEMPORAL>6.5</CVSS_TEMPORAL>
            <IS_EXPLOITABLE>0</IS_EXPLOITABLE>
            <PATCH_AVAILABLE>1</PATCH_AVAILABLE>
            <FIRST_FOUND_DATETIME>2024-10-10T08:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2024-10-18T08:00:00Z</LAST_FOUND_DATETIME>
            <VULN_INFO>
              <TITLE>OpenSSL Denial of Service Vulnerability</TITLE>
              <CVE_ID_LIST><CVE_ID>CVE-2024-0727</CVE_ID></CVE_ID_LIST>
              <SOLUTION>Upgrade OpenSSL to 3.0.13 or later</SOLUTION>
            </VULN_INFO>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
      <HOST>
        <IP>10.0.1.22</IP>
        <DNS>dns-server</DNS>
        <OS>Ubuntu 22.04</OS>
        <DETECTION_LIST>
          <DETECTION>
            <QID>38173</QID>
            <SEVERITY>5</SEVERITY>
            <CVSS_BASE>9.1</CVSS_BASE>
            <CVSS_TEMPORAL>7.9</CVSS_TEMPORAL>
            <IS_EXPLOITABLE>1</IS_EXPLOITABLE>
            <PATCH_AVAILABLE>0</PATCH_AVAILABLE>
            <FIRST_FOUND_DATETIME>2024-10-15T08:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2024-10-18T08:00:00Z</LAST_FOUND_DATETIME>
            <VULN_INFO>
              <TITLE>Linux Kernel Privilege Escalation</TITLE>
              <CVE_ID_LIST><CVE_ID>CVE-2024-1086</CVE_ID></CVE_ID_LIST>
              <SOLUTION>Update kernel to 6.6.15 or apply vendor patch</SOLUTION>
            </VULN_INFO>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>"""


def run_demo(output: str, severity_filter: list[int]):
    print("[*] Running in demo mode (no API credentials)\n")
    vulns = parse_detections_xml(DEMO_XML)
    if severity_filter:
        vulns = [v for v in vulns if v.severity in severity_filter]
    print_summary(vulns)
    if output:
        export_csv(vulns, output)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Qualys VMDR API wrapper — pull and export vulnerability data")
    parser.add_argument("--severity", default="4,5", help="Comma-separated severity levels (1-5), default: 4,5")
    parser.add_argument("--host", default=None, help="Filter by host IP")
    parser.add_argument("--output", default=None, help="CSV output path")
    parser.add_argument("--demo", action="store_true", help="Run with sample data")
    args = parser.parse_args()

    severity_filter = [int(s.strip()) for s in args.severity.split(",") if s.strip().isdigit()]

    if args.demo or not (QUALYS_USERNAME and QUALYS_PASSWORD):
        run_demo(args.output, severity_filter)
        return

    client = QualysClient(QUALYS_BASE_URL, QUALYS_USERNAME, QUALYS_PASSWORD)
    xml_data = client.get_host_detections(severity_filter=severity_filter, host_ip=args.host)

    if not xml_data:
        print("[!] No data returned from API")
        return

    vulns = parse_detections_xml(xml_data)
    vulns = [v for v in vulns if v.severity in severity_filter]
    print_summary(vulns)

    if args.output:
        export_csv(vulns, args.output)


if __name__ == "__main__":
    main()
