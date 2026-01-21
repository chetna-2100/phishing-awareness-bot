from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from .database import Base

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    input_type = Column(String(20))      # url / email / text etc.
    input_value = Column(String(500))
    prediction = Column(String(50))      # phishing / safe
    timestamp = Column(DateTime, default=datetime.utcnow)
