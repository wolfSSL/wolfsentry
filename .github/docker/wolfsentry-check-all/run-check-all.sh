#!/bin/bash
# Usage: run-check-all.sh <analyze-all|check|check-extra>, from a directory
# holding wolfsentry/, third/ (FreeRTOS, patched lwIP) and wolfssl/.

set -euo pipefail

group="$1"
top="$(pwd)"

git config --global --add safe.directory '*'
mkdir -p "$top/analyzer-root/scripts"
: > "$top/analyzer-root/scripts/analyzer-config.sh"

cd "$top/wolfsentry"

case "$group" in
analyze-all)
    # Ubuntu packages no big-endian ARM cross toolchain.
    targets=$(sed -n 's/^analyze-all: //p' Makefile.analyzers | sed 's/\<sanitize-armeb-test\>//')
    ;;
check-extra)
    # Ubuntu's arm-none-eabi-gcc 14 output exceeds the fixed 230000 byte image limit.
    targets=$(sed -n 's/^check-extra: //p' Makefile.analyzers | sed -E 's/\<freertos-arm32-(thumb-)?build-test\>//g')
    ;;
*)
    targets="$group"
    ;;
esac

# .WAIT is only valid in a prerequisite list, so honor it by running each side separately.
IFS='|' read -r -a phases <<< "${targets//.WAIT/|}"
for phase in "${phases[@]}"; do
    # shellcheck disable=SC2086
    make -j"$(nproc)" TMPDIR=/tmp REPO_ROOT="$top/analyzer-root" CLANG_PATH=/usr/bin \
        NOTIFICATION_SANDBOX= UNITTEST_LIST_JSON_DOM_EXTRAS=test_json_corpus $phase
done
