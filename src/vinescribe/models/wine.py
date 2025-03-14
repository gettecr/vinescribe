from pydantic import BaseModel
from typing import List, Optional


class NoteModel(BaseModel):
    smell: List[str]
    taste: List[str]
    verdict: str


class WineModel(BaseModel):
    date: str
    wine: str
    vintage: str
    varietal: str
    notes: NoteModel
    additional_notes: Optional[str] = None
