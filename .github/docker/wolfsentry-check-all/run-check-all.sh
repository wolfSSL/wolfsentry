#!/bin/bash
# Usage: run-check-all.sh <analyze-all|check|check-extra>, from a directory holding
# wolfsentry/, third/ (FreeRTOS, patched lwIP), wolfssl/ and JSON-Schema-Test-Suite/.

set -euo pipefail

group="$1"
top="$(pwd)"

git config --global --add safe.directory '*'
mkdir -p "$top/analyzer-root/scripts"
: > "$top/analyzer-root/scripts/analyzer-config.sh"

if [ -d "$top/JSON-Schema-Test-Suite/tests/latest/." ]; then
    export JSON_TEST_CORPUS_DIR="$top/JSON-Schema-Test-Suite/tests/latest/."
fi

cd "$top/wolfsentry"

case "$group" in
check-extra)
    # The FreeRTOS image size limits are tuned to a different arm-none-eabi-gcc than Ubuntu ships.
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
