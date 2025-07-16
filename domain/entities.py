
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class Task:
    title: str  
    description: Optional[str] = None
    completed: bool = False
    id: Optional[int] = None  
    created_at: datetime = datetime.now()