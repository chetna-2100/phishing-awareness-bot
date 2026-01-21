from sqlmodel import Session, select
from .models import ScanHistory
from .database import engine

def create_history(session: Session, scan_type: str, input_data: str, result: str):
    record = ScanHistory(scan_type=scan_type, input_data=input_data, result=result)
    session.add(record)
    session.commit()
    session.refresh(record)
    return record

def get_all_history(session: Session, limit: int = 200):
    stmt = select(ScanHistory).order_by(ScanHistory.timestamp.desc()).limit(limit)
    return session.exec(stmt).all()
