#!/bin/bash

set -euo pipefail

service_log=$(mktemp)
service_pid=

cleanup() {
    if [[ -n "$service_pid" ]]; then
        kill "$service_pid" 2>/dev/null || true
        wait "$service_pid" 2>/dev/null || true
    fi
    rm -f "$service_log"
}
trap cleanup EXIT

/usr/bin/python3 tests/notification-dbus-service.py >"$service_log" 2>&1 &
service_pid=$!

for attempt in $(seq 1 30); do
    if grep -q -F 'notification service ready' "$service_log"; then
        break
    fi
    if ! kill -0 "$service_pid" 2>/dev/null; then
        cat "$service_log"
        exit 1
    fi
    if [[ "$attempt" -eq 30 ]]; then
        cat "$service_log"
        exit 1
    fi
    sleep 1
done

make -j2 NOTIFICATION_SANDBOX= notification-demo-build-test
grep -q -F 'notification received:' "$service_log"
