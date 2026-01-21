from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database import SessionLocal, URL

app = FastAPI()

class URLRequest(BaseModel):
    url: str

# DB Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/save-url")
def save_url(request: URLRequest, db: Session = Depends(get_db)):

    # Check if URL exists
    existing = db.query(URL).filter(URL.url == request.url).first()
    if existing:
        return {"message": "URL already exists", "id": existing.id}

    new_url = URL(url=request.url)
    db.add(new_url)
    db.commit()
    db.refresh(new_url)

    return {"message": "URL saved", "id": new_url.id}
