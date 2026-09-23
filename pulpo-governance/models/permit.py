from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

@dataclass
class Permit:
    id: str
    subject: str
    capability: str
    model_id: Optional[str]
    max_tokens: Optional[int]
    max_calls: int
    remaining_calls: int
    max_cost: Optional[float]
    expires_at: datetime
    allowed_tags: List[str]
    used: bool = False
