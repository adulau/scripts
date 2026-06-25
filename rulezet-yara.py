#!/usr/bin/env python3
"""
Fetch YARA rules from Rulezet and optionally run them locally.

Examples:
  # Print matching rules
  python rulezet_yara.py --search CVE-2025-53521 --print-rules

  # Save rules locally
  python rulezet_yara.py --search CVE-2025-53521 --save-dir ./rules

  # Fetch + run against one file
  python rulezet_yara.py --search CVE-2025-53521 --run ./sample.bin

  # Fetch + run against a directory recursively
  python rulezet_yara.py --search CVE-2025-53521 --run /tmp/suspicious --recursive
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests


DEFAULT_API_BASE = "https://rulezet.org"
DEFAULT_TIMEOUT = 30


@dataclass
class RuleEntry:
    uuid: str
    title: str
    description: str
    author: str
    creation_date: str
    format: str
    content: str


def eprint(*args: object, **kwargs: object) -> None:
    print(*args, file=sys.stderr, **kwargs)


def sanitize_filename(value: str) -> str:
    value = value.strip().replace(" ", "_")
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value[:180].strip("._-") or "rule"


def fetch_rules(
    search: str,
    api_base: str = DEFAULT_API_BASE,
    timeout: int = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
) -> List[RuleEntry]:
    url = f"{api_base.rstrip('/')}/api/rule/public/search"
    headers = {"accept": "application/json"}
    params = {"search": search}

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=timeout,
            verify=verify_tls,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"HTTP request failed: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError("API did not return valid JSON") from exc

    results = payload.get("results", [])
    if not isinstance(results, list):
        raise RuntimeError("Unexpected API response: 'results' is not a list")

    out: List[RuleEntry] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        if item.get("format") != "yara":
            continue
        content = item.get("content")
        if not isinstance(content, str) or not content.strip():
            continue

        out.append(
            RuleEntry(
                uuid=str(item.get("uuid", "")),
                title=str(item.get("title", "")),
                description=str(item.get("description", "")),
                author=str(item.get("author", "")),
                creation_date=str(item.get("creation_date", "")),
                format=str(item.get("format", "")),
                content=content,
            )
        )

    return out


def save_rules(rules: List[RuleEntry], save_dir: Path) -> List[Path]:
    save_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    for rule in rules:
        base = sanitize_filename(rule.title or rule.uuid or "rule")
        suffix = sanitize_filename(rule.uuid) if rule.uuid else "no_uuid"
        path = save_dir / f"{base}__{suffix}.yar"
        path.write_text(rule.content, encoding="utf-8", newline="\n")
        written.append(path)

    return written


def print_rules(rules: List[RuleEntry]) -> None:
    for idx, rule in enumerate(rules, start=1):
        print(f"===== RULE {idx} =====")
        print(f"Title       : {rule.title}")
        print(f"UUID        : {rule.uuid}")
        print(f"Author      : {rule.author}")
        print(f"Created     : {rule.creation_date}")
        print(f"Description : {rule.description}")
        print(rule.content.rstrip())
        print()


def compile_yara_rules(rules: List[RuleEntry]):
    try:
        import yara  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "yara-python is not installed. Install it before using --run."
        ) from exc

    # Use namespaces so duplicate rule names from different results don't collide.
    sources: Dict[str, str] = {}
    for idx, rule in enumerate(rules, start=1):
        namespace = f"rulezet_{idx}_{sanitize_filename(rule.uuid or rule.title)}"
        sources[namespace] = rule.content

    try:
        return yara.compile(sources=sources)
    except Exception as exc:
        raise RuntimeError(f"Failed to compile YARA rules: {exc}") from exc


def iter_scan_targets(path: Path, recursive: bool) -> Iterable[Path]:
    if path.is_file():
        yield path
        return

    if not path.is_dir():
        raise RuntimeError(f"Target path does not exist or is not accessible: {path}")

    if recursive:
        for root, _, files in os.walk(path):
            for name in files:
                yield Path(root) / name
    else:
        for entry in path.iterdir():
            if entry.is_file():
                yield entry


def scan_with_yara(
    compiled_rules,
    target: Path,
    recursive: bool = False,
    timeout: Optional[int] = None,
    fast: bool = False,
) -> Dict[str, Any]:
    results: Dict[str, Any] = {"target": str(target), "matches": []}

    for file_path in iter_scan_targets(target, recursive=recursive):
        try:
            match_kwargs = {"fast": fast}
            if timeout is not None:
                match_kwargs["timeout"] = int(timeout)
            matches = compiled_rules.match(str(file_path), **match_kwargs)
        except Exception as exc:
            results["matches"].append(
                {
                    "file": str(file_path),
                    "error": str(exc),
                }
            )
            continue

        if not matches:
            continue

        file_matches = []
        for match in matches:
            file_matches.append(
                {
                    "rule": getattr(match, "rule", ""),
                    "namespace": getattr(match, "namespace", ""),
                    "tags": list(getattr(match, "tags", []) or []),
                    "meta": dict(getattr(match, "meta", {}) or {}),
                }
            )

        results["matches"].append(
            {
                "file": str(file_path),
                "matched_rules": file_matches,
            }
        )

    return results


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch YARA rules from Rulezet and optionally run them locally."
    )
    parser.add_argument(
        "--search",
        required=True,
        help="Search term sent to Rulezet, for example: CVE-2025-53521",
    )
    parser.add_argument(
        "--api-base",
        default=DEFAULT_API_BASE,
        help=f"Rulezet base URL (default: {DEFAULT_API_BASE})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--print-rules",
        action="store_true",
        help="Print fetched YARA rules to stdout",
    )
    parser.add_argument(
        "--save-dir",
        type=Path,
        help="Directory where fetched rules will be saved as .yar files",
    )
    parser.add_argument(
        "--run",
        type=Path,
        help="File or directory to scan locally with the fetched rules",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively scan subdirectories when --run points to a directory",
    )
    parser.add_argument(
        "--scan-timeout",
        type=int,
        default=None,
        help="Per-file YARA scan timeout in seconds",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Enable YARA fast mode during scanning",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print scan results as JSON",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        rules = fetch_rules(
            search=args.search,
            api_base=args.api_base,
            timeout=args.timeout,
            verify_tls=not args.insecure,
        )
    except Exception as exc:
        eprint(f"[!] Failed to fetch rules: {exc}")
        return 1

    if not rules:
        eprint("[!] No YARA rules found for that search.")
        return 2

    print(f"[+] Found {len(rules)} YARA rule(s) for search={args.search!r}")

    if args.print_rules:
        print_rules(rules)

    if args.save_dir:
        try:
            written = save_rules(rules, args.save_dir)
        except Exception as exc:
            eprint(f"[!] Failed to save rules: {exc}")
            return 1

        for path in written:
            print(f"[+] Saved: {path}")

    if args.run:
        try:
            compiled = compile_yara_rules(rules)
            scan_result = scan_with_yara(
                compiled_rules=compiled,
                target=args.run,
                recursive=args.recursive,
                timeout=args.scan_timeout,
                fast=args.fast,
            )
        except Exception as exc:
            eprint(f"[!] Scan failed: {exc}")
            return 1

        if args.json:
            print(json.dumps(scan_result, indent=2))
        else:
            matches = scan_result.get("matches", [])
            if not matches:
                print("[+] No matches.")
            else:
                print("[+] Matches:")
                for entry in matches:
                    file_name = entry.get("file", "<unknown>")
                    if "error" in entry:
                        print(f"  - {file_name}: ERROR: {entry['error']}")
                        continue

                    matched_rules = entry.get("matched_rules", [])
                    print(f"  - {file_name}")
                    for mr in matched_rules:
                        rule = mr.get("rule", "")
                        namespace = mr.get("namespace", "")
                        print(f"      * rule={rule} namespace={namespace}")
                        meta = mr.get("meta") or {}
                        if meta:
                            print(f"        meta={json.dumps(meta, ensure_ascii=False)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
