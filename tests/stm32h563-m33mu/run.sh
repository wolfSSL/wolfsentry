#!/bin/sh

set -eu

image=${1:?usage: run.sh image.bin expected-marker}
marker=${2:?usage: run.sh image.bin expected-marker}
emulator=${M33MU:-m33mu}
timeout_seconds=${M33MU_TIMEOUT:-30}
log=$(mktemp)
status_file=$(mktemp)
trap 'rm -f "$log" "$status_file"' EXIT INT TERM

(
    set +e
    "$emulator" --cpu stm32h563 --no-tz --uart-stdout \
        --expect-bkpt 0x7f --quit-on-faults --timeout "$timeout_seconds" \
        "$image" 2>&1
    printf '%s\n' "$?" > "$status_file"
) | tee "$log"
status=$(cat "$status_file")

grep -F 'M33MU: STM32H563 booted' "$log"
grep -F 'M33MU: FreeRTOS task started' "$log"
grep -F 'M33MU: lwIP TCP/IP task started' "$log"
grep -F "$marker" "$log"
grep -F '[EXPECT BKPT] Success' "$log"

if grep -Eq '^\[(MEMFAULT|BUSFAULT|USAGEFLT|HARDFLT)\]|HardFault|SecureFault' "$log"; then
    echo 'M33MU reported a processor fault' >&2
    exit 1
fi

exit "$status"
