# security-automation-toolkit

A collection of Python scripts I built to automate repetitive SOC tasks — log analysis, vulnerability data pulls, and CVE triage. Each script runs standalone with no external dependencies beyond `requests`, and includes a demo mode so you can see the output without any credentials.

---

## Tools

### `log-parser/log_parser.py` — Security Log Parser

Parses Windows Security Event logs (CSV) and Linux auth logs. Extracts failed logons, flags accounts exceeding a threshold, and identifies source IPs — the kind of thing you'd normally spend 20 minutes grepping through manually.

```bash
# Run demo (no log file needed)
python log-parser/log_parser.py

# Parse a real Windows event log export
python log-parser/log_parser.py --file security_events.csv --type windows --threshold 5

# Parse Linux auth log
python log-parser/log_parser.py --file /var/log/auth.log --type linux
```

Sample output:
```
[HIGH] jsmith
  Failures  : 6
  Source IPs: 203.0.113.42
  First seen: 2024-10-18 08:01:22
  Last seen : 2024-10-18 08:01:27
  Reasons   : Wrong password, Account locked out

[MEDIUM] administrator
  Failures  : 3
  Source IPs: 198.51.100.7, 198.51.100.8, 198.51.100.9
  Reasons   : Account does not exist
```

---

### `qualys-api/qualys_api.py` — Qualys VMDR Wrapper

Pulls vulnerability scan results from the Qualys VMDR API, filters by severity, and exports a prioritized CSV. Replaces the manual report export workflow — in production this fed directly into our Jira ticket automation.

```bash
# Demo mode (no credentials needed)
python qualys-api/qualys_api.py --demo

# Pull critical/high findings and export CSV
python qualys-api/qualys_api.py --severity 4,5 --output vulns.csv

# Filter to a specific host
python qualys-api/qualys_api.py --host 10.0.1.20 --severity 5 --output host_vulns.csv
```

Set credentials via environment variables:
```bash
export QUALYS_BASE_URL="https://qualysapi.qualys.com"
export QUALYS_USERNAME="your_username"
export QUALYS_PASSWORD="your_password"
```

Sample output:
```
Qualys VMDR Summary — 2024-10-18 09:15
Total findings : 3
  Critical      : 2
  High          : 1
  Exploitable   : 2
  Patch available: 2

Top findings by CVSS:
  [Critical] 10.0.1.20 | CVE-2024-21334 | CVSS 9.8 | SLA 3d [EXPLOITABLE]
  [Critical] 10.0.1.22 | CVE-2024-1086  | CVSS 9.1 | SLA 3d [EXPLOITABLE]
  [High]     10.0.1.20 | CVE-2024-0727  | CVSS 7.5 | SLA 14d
```

---

### `cve-lookup/cve_lookup.py` — CVE Lookup Tool

Queries the NIST NVD API for a CVE ID and returns CVSS scores, attack characteristics, affected products, and CISA KEV status. Handy during incident response when a CVE shows up and you need context fast without opening a browser.

```bash
# Look up a CVE (uses demo data if NVD is unreachable)
python cve-lookup/cve_lookup.py --cve CVE-2021-44228

# Include CISA KEV check
python cve-lookup/cve_lookup.py --cve CVE-2024-21334 --check-kev

# Output as JSON for piping/automation
python cve-lookup/cve_lookup.py --cve CVE-2021-44228 --json
```

Sample output:
```
CVE-2021-44228
CVSS v3 Score  : 10.0 CRITICAL
CVSS v3 Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Attack Characteristics:
  Vector            : NETWORK
  Complexity        : LOW
  Privileges needed : NONE

⚠  IN CISA KEV — Patch deadline: 2021-12-24
⚠  Ransomware use: Known

Risk flags: ⚠ CISA KEV | CVSS Critical | Network/Low-complexity | No auth required
```

---

## Setup

```bash
git clone https://github.com/cybergirlApurva/security-automation-toolkit.git
cd security-automation-toolkit
pip install -r requirements.txt
```

All three scripts run in demo mode without any credentials or external connections — just run them and you'll see sample output.

---

## Related Projects

- [`siem-detection-rules`](https://github.com/cybergirlApurva/siem-detection-rules) — KQL rules that generate the alerts these scripts help triage
- [`soar-playbooks`](https://github.com/cybergirlApurva/soar-playbooks) — FortiSOAR playbooks that consume Qualys data for automated ticket routing

---

*Apurva Tiwari · [LinkedIn](https://linkedin.com/in/apurva-tiwari) · MS Cybersecurity, George Washington University*
