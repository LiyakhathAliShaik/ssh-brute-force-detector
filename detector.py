#!/usr/bin/env python3
"""Defensive SSH failed-login detector for Linux authentication logs or sample logs."""

import argparse
import csv
import re
from collections import defaultdict
from datetime import datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

# Supports common sshd messages such as:
# Failed password for root from 203.0.113.10 port 4567 ssh2
# Failed password for invalid user admin from 203.0.113.10 port 4567 ssh2
FAILED_LOGIN_RE = re.compile(
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SYSLOG_PREFIX_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
)
MONTHS = {name: number for number, name in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1
)}


def parse_syslog_timestamp(line: str, year: int) -> datetime | None:
    """Parse the month/day/time portion of a traditional Linux syslog line."""
    match = SYSLOG_PREFIX_RE.search(line)
    if not match:
        return None
    try:
        return datetime(
            year,
            MONTHS[match.group("month")],
            int(match.group("day")),
            *map(int, match.group("time").split(":")),
        )
    except (KeyError, ValueError):
        return None


def analyze_log(log_path: Path, threshold: int, window_minutes: int, year: int):
    """Return per-IP totals and IPs exceeding threshold within the time window."""
    events = defaultdict(list)
    total_failed = 0
    unparsed_timestamps = 0

    with log_path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            match = FAILED_LOGIN_RE.search(line)
            if not match:
                continue

            try:
                source_ip = str(ip_address(match.group("ip")))
            except ValueError:
                continue

            total_failed += 1
            timestamp = parse_syslog_timestamp(line, year)
            if timestamp is None:
                unparsed_timestamps += 1
            else:
                events[source_ip].append(timestamp)

    results = []
    for source_ip, timestamps in sorted(events.items()):
        timestamps.sort()
        max_in_window = 0
        left = 0
        for right, current in enumerate(timestamps):
            while current - timestamps[left] > timedelta(minutes=window_minutes):
                left += 1
            max_in_window = max(max_in_window, right - left + 1)

        results.append({
            "ip_address": source_ip,
            "failed_attempts": len(timestamps),
            "max_attempts_in_window": max_in_window,
            "alert": max_in_window >= threshold,
        })

    # Include IPs whose timestamps could not be parsed in total counts,
    # but do not claim they crossed a time-window threshold.
    parsed_total = sum(len(item) for item in events.values())
    return results, total_failed, unparsed_timestamps, parsed_total


def write_csv(results, output_path: Path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "ip_address", "failed_attempts",
                "max_attempts_in_window", "alert"
            ],
        )
        writer.writeheader()
        writer.writerows(results)


def main():
    parser = argparse.ArgumentParser(
        description="Detect repeated failed SSH password attempts in authentication logs."
    )
    parser.add_argument("--log", default="sample_auth.log",
                        help="Path to the authentication log (default: sample_auth.log)")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts needed to trigger an alert (default: 5)")
    parser.add_argument("--window", type=int, default=5,
                        help="Time window in minutes (default: 5)")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="Year used to interpret syslog timestamps (default: current year)")
    parser.add_argument("--csv", default="reports/detection_report.csv",
                        help="CSV report path (default: reports/detection_report.csv)")
    args = parser.parse_args()

    if args.threshold < 1 or args.window < 1:
        parser.error("--threshold and --window must be positive integers")

    log_path = Path(args.log)
    if not log_path.is_file():
        parser.error(f"Log file not found: {log_path}")

    results, total_failed, unparsed, parsed_total = analyze_log(
        log_path, args.threshold, args.window, args.year
    )

    print("\n=== SSH BRUTE-FORCE DETECTION REPORT ===")
    print(f"Log file: {log_path}")
    print(f"Failed login events found: {total_failed}")
    print(f"Detection rule: at least {args.threshold} attempts in {args.window} minutes")
    print("\nIP address       Total parsed failures   Max in window   Status")
    print("-" * 68)

    if not results:
        print("No timestamped failed SSH login attempts were found.")

    for item in results:
        status = "ALERT" if item["alert"] else "No alert"
        print(
            f'{item["ip_address"]:<16} '
            f'{item["failed_attempts"]:<23} '
            f'{item["max_attempts_in_window"]:<15} {status}'
        )

    if unparsed:
        print(f"\nNote: {unparsed} failed-login line(s) had unrecognized timestamps.")
        print("They are included in the event total but excluded from time-window detection.")

    alerts = [item for item in results if item["alert"]]
    print(f"\nAlerts generated: {len(alerts)}")
    output_path = Path(args.csv)
    write_csv(results, output_path)
    print(f"CSV report saved to: {output_path}")
    print("\nReminder: An alert is an indicator for investigation, not proof of compromise.")


if __name__ == "__main__":
    main()
