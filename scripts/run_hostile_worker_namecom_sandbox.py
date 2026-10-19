#!/usr/bin/env python3
"""Retired Hostile Worker V0 sandbox harness.

This file intentionally cannot execute a sandbox purchase. The previous version
constructed its own request/quote/order and used a kernel policy that did not
require the independent approval ceremony. That path is weaker than the PR #83
admission contract and must never be accepted as admission evidence.

Use ``scripts/run_hostile_worker_namecom_ceremony.py`` instead. The replacement
is a thin client of the hostile-worker custody HTTP surface and the existing
independent authority service:

    domain only
    -> custody ProposalCommitment
    -> custody-generated authority request
    -> independently signed approval
    -> authorization by commitment reference
    -> one sandbox transmission
    -> independent reconciliation

No compatibility fallback exists here by design.
"""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "retired: weaker direct-order sandbox harness is not PR #83 admission evidence; "
        "use scripts/run_hostile_worker_namecom_ceremony.py",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
