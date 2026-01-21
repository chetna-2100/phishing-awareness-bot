from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session
from ..database import get_session
from ..models import ScanHistory
from ..crud import create_history, get_all_history
from typing import List

router = APIRouter(prefix="/history", tags=["history"])

@router.post("/add")
def add_history(payload: ScanHistory, session: Session = Depends(get_session)):
    # Accepts JSON matching ScanHistory fields (scan_type, input_data, result)
    try:
        r = create_history(session, payload.scan_type, payload.input_data, payload.result)
        return {"message": "saved", "id": r.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/all", response_model=List[ScanHistory])
def read_history(limit: int = 200, session: Session = Depends(get_session)):
    return get_all_history(session, limit)
