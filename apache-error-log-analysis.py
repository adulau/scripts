#!/usr/bin/env python3
"""
Parse Apache/PHP error logs for scanner activity.

Examples:
  python3 scan_stats.py /var/log/apache2/error.log*
  python3 scan_stats.py --top 50 --bucket hour error.log error.log.1.gz
"""

import argparse
import csv
import gzip
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

LOG_RE = re.compile(
    r"""
    ^(?:[^:]+:)?                              # optional grep/file prefix, e.g. error.log.1:
    \[(?P<timestamp>[^\]]+)\]\s+
    \[[^\]]+\]\s+
    \[pid[^\]]*\]\s+
    \[client\s+(?P<client>[^\]]+)\]\s+
    script\s+'(?P<path>[^']+)'\s+
    not\ found|unable\ to\ stat
    """,
    re.VERBOSE,
)

# More reliable alternative to the last part of the regex above:
LINE_RE = re.compile(
    r"""
    ^(?:[^:]+:)?                              # Optional filename prefix
    \[(?P<timestamp>[^\]]+)\].*?
    \[client\s+(?P<client>[^\]]+)\].*?
    script\s+'(?P<path>[^']+)'\s+
    (?:not\ found|not found|unable\ to\ stat)
    """,
    re.VERBOSE,
)


def open_log(filename: str):
    """Open regular or gzip-compressed logs."""
    if filename.endswith(".gz"):
        return gzip.open(filename, "rt", encoding="utf-8", errors="replace")
    return open(filename, "rt", encoding="utf-8", errors="replace")


def client_ip(client: str) -> str:
    """
    Remove the port from Apache's client field.
    Handles IPv4:port and typical IPv6:port representations.
    """
    client = client.strip()

    # Apache may emit bracketed IPv6 addresses: [2001:db8::1]:443
    if client.startswith("[") and "]" in client:
        return client[1:client.index("]")]

    # IPv4:port or unbracketed IPv6:port
    host, sep, port = client.rpartition(":")
    if sep and port.isdigit():
        return host
    return client


def parse_timestamp(value: str):
    """Parse Apache timestamps such as 'Wed Jun 24 08:37:14.881115 2026'."""
    value = value.strip()
    for fmt in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    return None


def write_csv(filename: str, headers: list[str], rows):
    with open(filename, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)


def print_table(title: str, headers: tuple[str, str], rows):
    print(f"\n{title}")
    print(f"{headers[0]:<55} {headers[1]:>10}")
    print("-" * 68)
    for name, count in rows:
        print(f"{name:<55.55} {count:>10}")


def main():
    parser = argparse.ArgumentParser(
        description="Create scanner statistics from Apache/PHP error logs."
    )
    parser.add_argument("logs", nargs="+", help="Log files to parse; .gz is supported")
    parser.add_argument("--top", type=int, default=20, help="Number of top results")
    parser.add_argument(
        "--bucket",
        choices=("hour", "day"),
        default="hour",
        help="Timeline aggregation interval",
    )
    parser.add_argument(
        "--output-prefix",
        default="scan_stats",
        help="Prefix for generated CSV files",
    )
    args = parser.parse_args()

    paths = Counter()
    ips = Counter()
    timeline = Counter()
    parsed = 0
    matched = 0

    for filename in args.logs:
        try:
            with open_log(filename) as handle:
                for line in handle:
                    parsed += 1
                    match = LINE_RE.search(line)
                    if not match:
                        continue

                    timestamp = parse_timestamp(match.group("timestamp"))
                    if not timestamp:
                        continue

                    path = match.group("path")
                    ip = client_ip(match.group("client"))

                    if args.bucket == "hour":
                        bucket = timestamp.strftime("%Y-%m-%d %H:00")
                    else:
                        bucket = timestamp.strftime("%Y-%m-%d")

                    paths[path] += 1
                    ips[ip] += 1
                    timeline[bucket] += 1
                    matched += 1

        except OSError as exc:
            print(f"Warning: cannot read {filename}: {exc}")

    top_paths = paths.most_common(args.top)
    top_ips = ips.most_common(args.top)
    timeline_rows = sorted(timeline.items())

    print(f"Parsed lines: {parsed:,}")
    print(f"Matching scanner requests: {matched:,}")
    print(f"Unique requested paths: {len(paths):,}")
    print(f"Unique client IPs: {len(ips):,}")

    print_table("Most common scanned paths", ("Path", "Requests"), top_paths)
    print_table("Top source IPs", ("IP address", "Requests"), top_ips)
    print_table(f"Timeline by {args.bucket}", (args.bucket.title(), "Requests"), timeline_rows)

    prefix = args.output_prefix
    write_csv(f"{prefix}_paths.csv", ["path", "requests"], paths.most_common())
    write_csv(f"{prefix}_ips.csv", ["ip", "requests"], ips.most_common())
    write_csv(
        f"{prefix}_timeline_{args.bucket}.csv",
        [args.bucket, "requests"],
        timeline_rows,
    )

    print(f"\nCSV output written to:")
    print(f"  {prefix}_paths.csv")
    print(f"  {prefix}_ips.csv")
    print(f"  {prefix}_timeline_{args.bucket}.csv")


if __name__ == "__main__":
    main()
