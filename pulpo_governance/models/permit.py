from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

class Permit(BaseModel):
    id: str
    subject: str
    capability: str
    model_id: Optional[str] = None
    max_tokens: Optional[int] = None
    max_calls: Optional[int] = None
    remaining_calls: Optional[int] = None
    max_cost: Optional[float] = None
    expires_at: Optional[datetime] = None
    allowed_tags: Optional[List[str]] = None
    used: Optional[bool] = False
