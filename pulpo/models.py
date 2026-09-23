# pulpo/models.py

from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class DomainPurchaseOrder:
    domain: str
    expires_at_ns: int
    buyer: Optional[str] = None
    price: Optional[int] = None
    order_id: Optional[str] = None

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "DomainPurchaseOrder":
        return cls(
            domain=payload["domain"],
            expires_at_ns=int(payload.get("expires_at_ns", payload.get("expires_at", 0))),
            buyer=payload.get("buyer"),
            price=payload.get("price"),
            order_id=payload.get("order_id"),
        )
