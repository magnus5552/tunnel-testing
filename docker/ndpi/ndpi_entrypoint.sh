#!/bin/bash
# ndpi_entrypoint.sh
#
# Wrapper around ndpiReader that transparently converts DLT_NULL (Windows /
# BSD loopback) PCAPs to DLT_RAW before analysis.
#
# ndpiReader 4.x silently skips packets with unsupported link types, so
# without this step every loopback capture from Windows produces 0 flows.
#
# The script:
#   1. Scans $@ for the -i <file> argument.
#   2. If the file exists and has DLT_NULL link-type, converts it to a
#      temp file and substitutes the path in the argument list.
#   3. Delegates to ndpiReader with the (possibly modified) args.

set -euo pipefail

NORMALIZE=/usr/local/bin/pcap_normalize.py
NDPI=ndpiReader

# ── find the -i argument value ────────────────────────────────────────────────
INPUT_FILE=""
INPUT_IDX=-1
args=("$@")
for i in "${!args[@]}"; do
    if [[ "${args[$i]}" == "-i" && $((i+1)) -lt ${#args[@]} ]]; then
        INPUT_FILE="${args[$((i+1))]}"
        INPUT_IDX=$i
        break
    fi
done

# ── normalise the pcap if needed ──────────────────────────────────────────────
if [[ -n "$INPUT_FILE" && -f "$INPUT_FILE" ]]; then
    TMP_PCAP="$(mktemp /tmp/ndpi_XXXXXX.pcap)"
    trap 'rm -f "$TMP_PCAP"' EXIT

    # pcap_normalize.py copies unchanged if link type is not DLT_NULL
    python3 "$NORMALIZE" "$INPUT_FILE" "$TMP_PCAP" >&2 || true

    # Substitute path in args
    args[$((INPUT_IDX+1))]="$TMP_PCAP"
fi

# ── run ndpiReader ────────────────────────────────────────────────────────────
exec "$NDPI" "${args[@]}"
