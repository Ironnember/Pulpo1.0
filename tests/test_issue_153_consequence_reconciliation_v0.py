"""Issue #153 compatibility bridge for explicit auto-renew observation evidence.

The original closure-grade suite is preserved verbatim in the non-discovered
base module. This wrapper updates only the historical test fixture default:
provider success cases that intend complete evidence now state the exact
`auto_renew_enabled=False` value explicitly. Tests may still pass
`auto_renew_enabled=None` to prove missing evidence remains unresolved.
"""

import tests.issue_153_consequence_reconciliation_v0_base as _base


NOW = _base.NOW
CUSTODY_SECRET = _base.CUSTODY_SECRET
KERNEL_SECRET = _base.KERNEL_SECRET
OPERATOR = _base.OPERATOR


class Issue153ConsequenceReconciliationV0(
    _base.Issue153ConsequenceReconciliationV0
):
    @staticmethod
    def _observation(provider_request_id: str, **changes):
        changes.setdefault("auto_renew_enabled", False)
        return _base.Issue153ConsequenceReconciliationV0._observation(
            provider_request_id,
            **changes,
        )
