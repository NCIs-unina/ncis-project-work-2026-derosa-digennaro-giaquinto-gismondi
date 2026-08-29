#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 RUN_ID EVENT"
    exit 1
fi

RUN_ID="$1"
EVENT="$2"

PROJECT_ROOT="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/.." &&
    pwd
)"

OUT="$PROJECT_ROOT/results/raw/${RUN_ID}_events.csv"

printf "%s,%s\n" \
    "$EVENT" \
    "$(date +%s.%N)" \
    >> "$OUT"
