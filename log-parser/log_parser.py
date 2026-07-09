"""
log_parser.py
=============
Parses Windows Security Event logs (exported as CSV or EVTX-converted text)
and Linux auth logs. Extracts failed logons, privilege escalations, and
account lockouts. Outputs a summary report and flags high-risk accounts.

I built this to cut down manual log review time in the SOC — instead of
grepping through thousands of lines, this spits out a prioritized list
of accounts and IPs worth investigating.

Usage:
    python log_parser.py --file auth.log --type linux
    python log_parser.py --file security_events.csv --type windows
    python log_parser.py --file security_events.csv --type windows --threshold 5

Author: Apurva Tiwari
"""

import argparse
import csv
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class LogonFailure:
    timestamp: str
    source_ip: str
    username: str
    reason: str
    event_id: str = ""


@dataclass
class AccountSummary:
    username: str
    failure_count: int = 0
    source_ips: set = field(default_factory=set)
    first_seen: str = ""
    last_seen: str = ""
    reasons: list = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if self.failure_count >= 20 or len(self.source_ips) >= 5:
            return "HIGH"
        elif self.failure_count >= 5:
            return "MEDIUM"
        return "LOW"


# ---------------------------------------------------------------------------
# Windows Security Event Log parser (CSV format)
# Expected columns: TimeGenerated, EventID, Account, IpAddress, LogonType, SubStatus
# ---------------------------------------------------------------------------

WINDOWS_FAILURE_EVENT_IDS = {"4625", "4740"}  # Failed logon, account lockout

SUBSTATUS_REASONS = {
    "0xC000006A": "Wrong password",
    "0xC0000064": "Account does not exist",
    "0xC0000234": "Account locked out",
    "0xC0000072": "Account disabled",
    "0xC000006F": "Logon outside allowed hours",
    "0xC0000070": "Workstation restriction",
}


def parse_windows_events(filepath: str, threshold: int) -> list[AccountSummary]:
    failures: list[LogonFailure] = []

    with open(filepath, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            event_id = row.get("EventID", "").strip()
            if event_id not in WINDOWS_FAILURE_EVENT_IDS:
                continue

            account = row.get("Account", "").strip().lower()
            if not account or account in ("system", "-", ""):
                continue
            # Skip machine accounts
            if account.endswith("$"):
                continue

            substatus = row.get("SubStatus", "").strip()
            reason = SUBSTATUS_REASONS.get(substatus, substatus or "Unknown")

            failures.append(LogonFailure(
                timestamp=row.get("TimeGenerated", "").strip(),
                source_ip=row.get("IpAddress", "-").strip(),
                username=account,
                reason=reason,
                event_id=event_id
            ))

    return _aggregate(failures, threshold)


# ---------------------------------------------------------------------------
# Linux auth.log parser
# Matches: sshd failed password, invalid user, PAM authentication failure
# ---------------------------------------------------------------------------

LINUX_FAILURE_PATTERNS = [
    # Failed SSH password
    re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*'
        r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)'
    ),
    # Invalid user
    re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*'
        r'Invalid user (?P<user>\S+) from (?P<ip>\S+)'
    ),
    # PAM failure
    re.compile(
        r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*'
        r'pam_unix.*authentication failure.*user=(?P<user>\S+)'
    ),
]


def parse_linux_auth(filepath: str, threshold: int) -> list[AccountSummary]:
    failures: list[LogonFailure] = []

    with open(filepath, encoding="utf-8", errors="ignore") as f:
        for line in f:
            for pattern in LINUX_FAILURE_PATTERNS:
                match = pattern.search(line)
                if match:
                    groups = match.groupdict()
                    ts = f"{groups.get('month','')} {groups.get('day','')} {groups.get('time','')}"
                    failures.append(LogonFailure(
                        timestamp=ts,
                        source_ip=groups.get("ip", "-"),
                        username=groups.get("user", "unknown").lower(),
                        reason="Authentication failure"
                    ))
                    break

    return _aggregate(failures, threshold)


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _aggregate(failures: list[LogonFailure], threshold: int) -> list[AccountSummary]:
    summaries: dict[str, AccountSummary] = defaultdict(lambda: AccountSummary(username=""))

    for f in failures:
        s = summaries[f.username]
        s.username = f.username
        s.failure_count += 1
        if f.source_ip and f.source_ip != "-":
            s.source_ips.add(f.source_ip)
        if not s.first_seen:
            s.first_seen = f.timestamp
        s.last_seen = f.timestamp
        if f.reason and f.reason not in s.reasons:
            s.reasons.append(f.reason)

    results = [s for s in summaries.values() if s.failure_count >= threshold]
    results.sort(key=lambda x: x.failure_count, reverse=True)
    return results


# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------

def print_report(summaries: list[AccountSummary], log_type: str):
    print(f"\n{'='*60}")
    print(f" Log Parser Report — {log_type.upper()} | {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*60}")
    print(f" Flagged accounts: {len(summaries)}")
    print(f"{'='*60}\n")

    if not summaries:
        print(" No accounts met the failure threshold.")
        return

    for s in summaries:
        print(f"[{s.risk_level}] {s.username}")
        print(f"  Failures  : {s.failure_count}")
        print(f"  Source IPs: {', '.join(sorted(s.source_ips)) or 'N/A'}")
        print(f"  First seen: {s.first_seen}")
        print(f"  Last seen : {s.last_seen}")
        print(f"  Reasons   : {', '.join(s.reasons)}")
        print()


# ---------------------------------------------------------------------------
# Demo mode — generates sample data so the script runs without a real log file
# ---------------------------------------------------------------------------

SAMPLE_WINDOWS_CSV = """TimeGenerated,EventID,Account,IpAddress,LogonType,SubStatus
2024-10-18 08:01:22,4625,jsmith,203.0.113.42,3,0xC000006A
2024-10-18 08:01:23,4625,jsmith,203.0.113.42,3,0xC000006A
2024-10-18 08:01:24,4625,jsmith,203.0.113.42,3,0xC000006A
2024-10-18 08:01:25,4625,jsmith,203.0.113.42,3,0xC000006A
2024-10-18 08:01:26,4625,jsmith,203.0.113.42,3,0xC000006A
2024-10-18 08:01:27,4625,jsmith,203.0.113.42,3,0xC000006A
2024-10-18 08:02:10,4625,administrator,198.51.100.7,3,0xC0000064
2024-10-18 08:02:11,4625,administrator,198.51.100.8,3,0xC0000064
2024-10-18 08:02:12,4625,administrator,198.51.100.9,3,0xC0000064
2024-10-18 08:03:00,4740,jsmith,203.0.113.42,3,0xC0000234
2024-10-18 08:05:00,4625,svc_backup,10.0.1.5,3,0xC000006A
2024-10-18 08:05:01,4625,svc_backup,10.0.1.5,3,0xC000006A
"""

SAMPLE_LINUX_LOG = """Oct 18 08:01:22 server sshd[1234]: Failed password for jsmith from 203.0.113.42 port 22 ssh2
Oct 18 08:01:25 server sshd[1234]: Failed password for jsmith from 203.0.113.42 port 22 ssh2
Oct 18 08:01:28 server sshd[1234]: Failed password for jsmith from 203.0.113.42 port 22 ssh2
Oct 18 08:01:31 server sshd[1234]: Failed password for jsmith from 203.0.113.42 port 22 ssh2
Oct 18 08:01:34 server sshd[1234]: Failed password for jsmith from 203.0.113.42 port 22 ssh2
Oct 18 08:02:10 server sshd[1235]: Invalid user admin from 198.51.100.7 port 44321
Oct 18 08:02:11 server sshd[1235]: Invalid user admin from 198.51.100.8 port 44322
Oct 18 08:03:00 server sshd[1236]: Failed password for root from 192.0.2.15 port 55001 ssh2
Oct 18 08:03:01 server sshd[1236]: Failed password for root from 192.0.2.15 port 55002 ssh2
Oct 18 08:03:02 server sshd[1236]: Failed password for root from 192.0.2.15 port 55003 ssh2
"""


def run_demo():
    import tempfile, os
    print("[*] No file specified — running in demo mode with sample data\n")

    # Windows demo
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(SAMPLE_WINDOWS_CSV)
        win_path = f.name
    results = parse_windows_events(win_path, threshold=3)
    print_report(results, "windows (demo)")
    os.unlink(win_path)

    # Linux demo
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(SAMPLE_LINUX_LOG)
        lin_path = f.name
    results = parse_linux_auth(lin_path, threshold=3)
    print_report(results, "linux (demo)")
    os.unlink(lin_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Parse security logs for failed logons and suspicious activity")
    parser.add_argument("--file", help="Path to log file (CSV for Windows, text for Linux)")
    parser.add_argument("--type", choices=["windows", "linux"], default="windows")
    parser.add_argument("--threshold", type=int, default=5, help="Min failures to flag an account (default: 5)")
    args = parser.parse_args()

    if not args.file:
        run_demo()
        return

    if not Path(args.file).exists():
        print(f"[!] File not found: {args.file}")
        return

    if args.type == "windows":
        results = parse_windows_events(args.file, args.threshold)
    else:
        results = parse_linux_auth(args.file, args.threshold)

    print_report(results, args.type)


if __name__ == "__main__":
    main()
