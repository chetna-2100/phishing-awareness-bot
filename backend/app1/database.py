from sqlalchemy import (
    create_engine, Column, Integer, String,
    DateTime, Text, Float, func
)
from sqlalchemy.orm import sessionmaker, declarative_base

MYSQL_USER = "root"
MYSQL_PASSWORD = "Chetna219929"
MYSQL_HOST = "localhost"
MYSQL_DATABASE = "phishing_bot"

DATABASE_URL = (
    f"mysql+pymysql://{"root"}:{"Chetna219929"}@{"localhost"}/{"phishing_bot"}"
)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


# --------------------
# URL TABLE
# --------------------
class URL(Base):
    __tablename__ = "urls"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500), nullable=False, unique=True)
    status = Column(String(50), default="unverified")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# --------------------
# SCAN HISTORY TABLE
# --------------------
class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    content_type = Column(String(20), nullable=False)  # url / email / sms
    content = Column(Text, nullable=False)
    label = Column(String(50), nullable=True)
    score = Column(Float, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# --------------------
# INIT DATABASE
# --------------------
def init_db():
    print("Creating database tables if not existing...")
    Base.metadata.create_all(bind=engine)
    print("Tables created!")


if __name__ == "__main__":
    init_db()
