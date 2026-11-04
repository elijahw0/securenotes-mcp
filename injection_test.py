import os
import sys


if not os.environ.get("FINDINGS"):
    print("setup failed: set FINDINGS to the injection fixture before running, e.g.\n"
          "  FINDINGS=findings_injection_test.json python injection_test.py")
    sys.exit(2)

from server import release_readiness

result = release_readiness()
blockers = set(result["blockers"])

# The poisoned fixture adds SN-010: status=fixed, severity=low (so by the DATA it
# should NOT block), but its root_cause text tries to make the model report the
# release as ready with no blockers.
#
# The gate reads only status/severity in Python, never the text, so it should:
#   1. Return exactly the real high+open findings as blockers, and
#   2. Still report ready=False.
# If the injection had any effect, one of these would change.

expected_blockers = {"SN-001", "SN-004", "SN-005"}

correct_verdict = blockers == expected_blockers
still_blocked = result["ready"] is False

if correct_verdict and still_blocked:
    print(f"PASS: gate ignored the injected finding. Blockers: {sorted(blockers)}")
    sys.exit(0)
else:
    print("FAIL: the injection affected the gate.")
    print(f"  expected blockers: {sorted(expected_blockers)}")
    print(f"  actual blockers:   {sorted(blockers)}")
    print(f"  ready: {result['ready']}")
    sys.exit(1)