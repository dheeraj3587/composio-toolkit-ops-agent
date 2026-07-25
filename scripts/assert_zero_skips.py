#!/usr/bin/env python3
"""Fail if a JUnit report shows any skipped (or zero) browser tests.

GitHub treats a skipped check as successful, so a real-browser suite that quietly
skips would look green while testing nothing. This asserts, independently of
pytest's own exit code, that the browser suite actually RAN with zero skips.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: assert_zero_skips.py <junit.xml>", file=sys.stderr)
        return 2
    try:
        root = ET.parse(sys.argv[1]).getroot()
    except (OSError, ET.ParseError) as exc:
        print(f"could not read JUnit report: {type(exc).__name__}", file=sys.stderr)
        return 2

    suites = list(root.iter("testsuite")) if root.tag == "testsuites" else [root]
    total = skipped = failures = errors = 0
    for suite in suites:
        total += int(suite.get("tests", 0))
        skipped += int(suite.get("skipped", 0))
        failures += int(suite.get("failures", 0))
        errors += int(suite.get("errors", 0))

    print(f"tests={total} skipped={skipped} failures={failures} errors={errors}")
    if total == 0:
        print("no browser tests ran at all", file=sys.stderr)
        return 1
    if skipped:
        print(f"{skipped} browser test(s) skipped; this gate requires zero skips", file=sys.stderr)
        return 1
    if failures or errors:
        print("browser tests failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
