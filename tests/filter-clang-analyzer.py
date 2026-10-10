#!/usr/bin/python3

"""Reject Clang analyzer results except documented file-local false positives."""

import json
import pathlib
import sys


ALLOWED_RESULTS = {
    ("core.uninitialized.Assign", "src/json/centijson_value.c", 1285),
    ("core.NullDereference", "src/json/centijson_value.c", 1483),
    ("core.NullDereference", "src/json/centijson_value.c", 1520),
}


def normalized_rule(rule_id):
    return rule_id.removeprefix("clang-analyzer-")


def result_location(result):
    locations = result.get("locations", [])
    if not locations:
        return "<unknown>", 0
    physical = locations[0].get("physicalLocation", {})
    location = physical.get("artifactLocation", {}).get("uri", "<unknown>")
    line = physical.get("region", {}).get("startLine", 0)
    return location, line


def main():
    report_dir = pathlib.Path(sys.argv[1])
    unexpected = []
    suppressed = 0

    for report_path in sorted(report_dir.rglob("*.sarif")):
        report = json.loads(report_path.read_text(encoding="utf-8"))
        for run in report.get("runs", []):
            for result in run.get("results", []):
                rule = normalized_rule(result.get("ruleId", "<unknown>"))
                location, line = result_location(result)
                allowed = any(
                    rule == allowed_rule
                    and location.endswith(allowed_path)
                    and line == allowed_line
                    for allowed_rule, allowed_path, allowed_line in ALLOWED_RESULTS
                )
                if allowed:
                    suppressed += 1
                else:
                    unexpected.append((rule, location, line))

    for rule, location, line in unexpected:
        print(f"unexpected Clang analyzer result: {rule} at {location}:{line}")
    print(f"suppressed {suppressed} documented analyzer result(s)")
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
