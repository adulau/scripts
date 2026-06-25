#!/usr/bin/env bash
#
# Disassemble a raw x86-64 byte sequence.
# Accepts either plain hex bytes or a pasted Linux kernel "Code:" line.
#
# Examples:
#   ./rawdisasm.sh --address 0x400000 '55 48 89 e5 5d c3'
#
#   ./rawdisasm.sh --rip 0x7f8ba1d7f009 \
#     'Code: e9 22 fa ff ff ... ff 15 3f 0a 03 00 <80> bb 37 03 00 00 00'
#
# The --rip form uses the byte wrapped in <...> as the faulting instruction
# and derives the beginning address of the displayed byte window.

set -euo pipefail

PROG="${0##*/}"

usage() {
    cat <<EOF
Usage:
  $PROG [options] --code '<hex bytes>'
  $PROG [options] '<hex bytes>'
  echo '<hex bytes>' | $PROG [options] --code -

Disassemble a raw machine-code byte string using GNU objdump.

Options:
  -c, --code STRING       Hex bytes, or a pasted kernel "Code:" line.
                           Use "-" to read the bytes from standard input.

  -a, --address ADDRESS   Virtual address of the first supplied byte.
                           Default: 0x0

  -r, --rip ADDRESS       Address of the faulting instruction. Requires a
                           kernel-style marker such as <80> in the code string.
                           The script calculates the byte-window start address.

  -m, --arch ARCH         objdump architecture. Default: i386:x86-64
                           Examples: i386, i386:x86-64

  -h, --help              Show this help text.

Examples:
  # Disassemble a simple byte sequence at address zero.
  $PROG '55 48 89 e5 5d c3'

  # Use a known start address.
  $PROG --address 0x7f8ba1d7efdf \\
    'e9 22 fa ff ff 66 66 2e 0f 1f 84 00 00 00 00 00 90'

  # Paste a kernel Code: line and map the marked byte to RIP.
  $PROG --rip 0x7f8ba1d7f009 \\
    'Code: e9 22 fa ff ff 66 66 2e 0f 1f 84 00 00 00 00 00 90 55 48 8d 2d 30 1a 03 00 53 48 89 fb 48 89 ef 48 83 ec 08 ff 15 3f 0a 03 00 <80> bb 37 03 00 00 00 75 14'

Notes:
  - Requires GNU objdump and xxd.
  - Non-byte text is ignored, so a pasted "Code:" prefix is accepted.
  - With --rip, the first byte enclosed in <...> is treated as the RIP byte.
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

code=""
start_address=""
rip=""
arch="i386:x86-64"

while (($#)); do
    case "$1" in
        -c|--code)
            (($# >= 2)) || die "missing value for $1"
            code="$2"
            shift 2
            ;;
        -a|--address)
            (($# >= 2)) || die "missing value for $1"
            start_address="$2"
            shift 2
            ;;
        -r|--rip)
            (($# >= 2)) || die "missing value for $1"
            rip="$2"
            shift 2
            ;;
        -m|--arch)
            (($# >= 2)) || die "missing value for $1"
            arch="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            [[ -z "$code" ]] || die "code was supplied more than once"
            code="$1"
            shift
            ;;
    esac
done

if (($#)); then
    die "unexpected argument: $1"
fi

[[ -n "$code" ]] || {
    usage >&2
    exit 1
}

command -v objdump >/dev/null || die "objdump was not found"
command -v xxd >/dev/null || die "xxd was not found"

if [[ "$code" == "-" ]]; then
    code="$(cat)"
fi

# Extract two-digit hexadecimal byte tokens. For --rip, remember which byte
# appeared inside <...>, as emitted by Linux's segfault Code: log.
mapfile -t parsed < <(
    printf '%s\n' "$code" |
    awk '
        BEGIN {
            count = 0
            fault_offset = -1
            hex = ""
        }

        {
            for (i = 1; i <= NF; i++) {
                token = $i
                marked = (token ~ /<[^>]+>/)

                gsub(/[<>\[\]\(\),;]/, "", token)
                sub(/^0[xX]/, "", token)

                if (token ~ /^[[:xdigit:]]{2}$/) {
                    if (marked && fault_offset < 0)
                        fault_offset = count

                    hex = hex tolower(token)
                    count++
                }
            }
        }

        END {
            print count, fault_offset
            print hex
        }
    '
)

metadata="${parsed[0]:-}"
hex="${parsed[1]:-}"

byte_count="${metadata%% *}"
fault_offset="${metadata##* }"

[[ "$byte_count" =~ ^[0-9]+$ ]] || die "could not parse any byte values"
(( byte_count > 0 )) || die "could not parse any byte values"
[[ "$hex" =~ ^[0-9a-f]+$ ]] || die "parsed byte stream is invalid"

normalize_hex() {
    local value="$1"
    value="${value#0x}"
    value="${value#0X}"

    [[ "$value" =~ ^[0-9a-fA-F]+$ ]] ||
        die "invalid hexadecimal address: $1"

    printf '%s' "$value"
}

if [[ -n "$start_address" && -n "$rip" ]]; then
    die "use either --address or --rip, not both"
fi

if [[ -n "$rip" ]]; then
    (( fault_offset >= 0 )) ||
        die "--rip requires a fault marker such as <80> in the code string"

    rip_hex="$(normalize_hex "$rip")"
    start_value=$((16#$rip_hex - fault_offset))
    (( start_value >= 0 )) || die "calculated start address is negative"

    printf -v start_hex '%x' "$start_value"
elif [[ -n "$start_address" ]]; then
    start_hex="$(normalize_hex "$start_address")"
else
    start_hex="0"
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

printf '%s' "$hex" | xxd -r -p >"$tmp"

echo "Architecture: $arch"
echo "Bytes:        $byte_count"
echo "Start:        0x$start_hex"

if (( fault_offset >= 0 )); then
    printf 'Marked byte:  offset 0x%x' "$fault_offset"
    if [[ -n "$rip" ]]; then
        printf ' (RIP: 0x%s)' "$(normalize_hex "$rip")"
    fi
    printf '\n'
fi

echo
objdump \
    -D \
    -b binary \
    -m "$arch" \
    -M intel \
    --adjust-vma="0x$start_hex" \
    "$tmp"
