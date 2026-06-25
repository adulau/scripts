#!/usr/bin/env python3
"""
Generate a YARA rule from newline-separated strings.

Examples:
  printf '%s\n' "evil.com" "C:\\Temp\\payload.exe" |
    ./strings_to_yara.py -n suspicious_indicators -a analyst -p "Example IOC rule"

  ./strings_to_yara.py -n suspicious_indicators -i indicators.txt \
    --min-matches 2 --modifier ascii --modifier wide --modifier nocase \
    -o suspicious_indicators.yar
"""

from __future__ import annotations

import argparse
import fileinput
import getpass
import hashlib
import re
import sys
from pathlib import Path
from typing import Iterable


YARA_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ALLOWED_MODIFIERS = {"ascii", "wide", "nocase", "fullword", "private"}


def yara_identifier(value: str) -> str:
    """Validate a YARA rule name or tag."""
    if not YARA_IDENTIFIER_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            f"{value!r} is not a valid YARA identifier. "
            "Use letters, digits, and underscores; do not start with a digit."
        )
    return value


def escape_yara_string(value: str) -> str:
    """
    Safely represent a Python string as a YARA text string.

    Non-printable and non-ASCII UTF-8 bytes are rendered as \\xNN sequences.
    """
    escaped: list[str] = []

    for byte in value.encode("utf-8"):
        if byte == ord('"'):
            escaped.append(r"\"")
        elif byte == ord("\\"):
            escaped.append(r"\\")
        elif byte == ord("\t"):
            escaped.append(r"\t")
        elif byte == ord("\r"):
            escaped.append(r"\r")
        elif byte == ord("\n"):
            escaped.append(r"\n")
        elif 0x20 <= byte <= 0x7E:
            escaped.append(chr(byte))
        else:
            escaped.append(f"\\x{byte:02X}")

    return "".join(escaped)


def read_strings(files: Iterable[str]) -> list[str]:
    """Read non-empty, unique lines while preserving input order."""
    strings: list[str] = []
    seen: set[str] = set()

    with fileinput.input(files=list(files), encoding="utf-8", errors="surrogateescape") as handle:
        for line in handle:
            value = line.rstrip("\r\n")

            # Ignore blank lines but preserve leading/trailing whitespace in indicators.
            if not value.strip() or value in seen:
                continue

            strings.append(value)
            seen.add(value)

    return strings


def build_condition(min_matches: int) -> str:
    if min_matches == 1:
        return "any of ($s*)"
    return f"{min_matches} of ($s*)"


def build_rule(
    *,
    name: str,
    author: str,
    purpose: str,
    tags: list[str],
    strings: list[str],
    modifiers: list[str],
    min_matches: int,
) -> str:
    source_hash = hashlib.sha256("\n".join(strings).encode("utf-8")).hexdigest()
    tag_section = f" : {' '.join(tags)}" if tags else ""
    modifier_section = f" {' '.join(modifiers)}" if modifiers else ""

    lines = [
        f"rule {name}{tag_section}",
        "{",
        "    meta:",
        f'        author = "{escape_yara_string(author)}"',
        f'        purpose = "{escape_yara_string(purpose)}"',
        '        generator = "strings_to_yara.py"',
        f"        string_count = {len(strings)}",
        f'        strings_sha256 = "{source_hash}"',
        "",
        "    strings:",
    ]

    for index, value in enumerate(strings):
        lines.append(
            f'        $s{index:03d} = "{escape_yara_string(value)}"{modifier_section}'
        )

    lines.extend(
        [
            "",
            "    condition:",
            f"        {build_condition(min_matches)}",
            "}",
        ]
    )

    return "\n".join(lines)


def validate_rule(rule_source: str) -> None:
    """Fail early when YARA rejects the generated rule."""
    try:
        import yara
    except ImportError as exc:
        raise RuntimeError(
            "Validation requires yara-python. Install it with: pip install yara-python\n"
            "Alternatively, use --no-validate."
        ) from exc

    try:
        yara.compile(source=rule_source)
    except yara.Error as exc:
        raise RuntimeError(f"Generated YARA rule is invalid: {exc}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a validated YARA rule from newline-separated strings.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-n",
        "--name",
        required=True,
        type=yara_identifier,
        help="YARA rule name",
    )
    parser.add_argument(
        "-a",
        "--author",
        default=getpass.getuser(),
        help="Rule author",
    )
    parser.add_argument(
        "-p",
        "--purpose",
        default="Purpose not set",
        help="Purpose or detection rationale",
    )
    parser.add_argument(
        "-i",
        "--input",
        action="append",
        default=[],
        metavar="FILE",
        help="Input file; repeatable. Reads stdin when omitted.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        help="Write the rule to this file instead of stdout.",
    )
    parser.add_argument(
        "--tag",
        action="append",
        type=yara_identifier,
        default=[],
        help="Rule tag; repeatable.",
    )
    parser.add_argument(
        "--modifier",
        action="append",
        choices=sorted(ALLOWED_MODIFIERS),
        default=None,
        help="YARA string modifier; repeatable.",
    )
    parser.add_argument(
        "--min-matches",
        type=int,
        default=1,
        metavar="N",
        help="Minimum number of generated strings required to match.",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Do not compile the generated rule with yara-python.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    input_files = args.input or ["-"]
    strings = read_strings(input_files)

    if not strings:
        print("Error: no non-empty strings were provided.", file=sys.stderr)
        return 2

    if args.min_matches < 1:
        print("Error: --min-matches must be at least 1.", file=sys.stderr)
        return 2

    if args.min_matches > len(strings):
        print(
            f"Error: --min-matches ({args.min_matches}) exceeds the number of "
            f"unique strings ({len(strings)}).",
            file=sys.stderr,
        )
        return 2

    modifiers = args.modifier or ["ascii", "wide"]

    if "wide" in modifiers and any(not value.isascii() for value in strings):
        print(
            "Warning: --wide is intended for ASCII/UTF-16LE-like strings. "
            "Non-ASCII input is emitted as UTF-8 byte escapes.",
            file=sys.stderr,
        )

    rule_source = build_rule(
        name=args.name,
        author=args.author,
        purpose=args.purpose,
        tags=args.tag,
        strings=strings,
        modifiers=modifiers,
        min_matches=args.min_matches,
    )

    if not args.no_validate:
        try:
            validate_rule(rule_source)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

    if args.output:
        args.output.write_text(rule_source + "\n", encoding="utf-8")
    else:
        print(rule_source)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
