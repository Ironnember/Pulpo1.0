"""Wire-authorization reference deployment (MOCK rail; no real funds).

A reference integration showing a payment-shaped consequence — a wire
transfer — reachable only through the canonical governance kernel: a
verified approval envelope mints a one-use permit bound to the exact
intent (principal, payee, amount, session), the permit is consumed, and
only then does the mock rail record a transfer.

The rail in this package is a mock. It moves no money, talks to no bank,
and every record it writes is marked ``MOCK-NO-REAL-FUNDS``.
"""

from .rail import MockPaymentRail
from .service import WireAuthorizationService, WireResult

__all__ = [
    "MockPaymentRail",
    "WireAuthorizationService",
    "WireResult",
]
