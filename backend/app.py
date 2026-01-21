from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import os
import uvicorn

# ----------------------------------------
# Paths
# ----------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model")

# ----------------------------------------
# Load Models
# ----------------------------------------
url_model = joblib.load(os.path.join(MODEL_DIR, "phishing_model.pkl"))

email_model = joblib.load(os.path.join(MODEL_DIR, "email_phishing_model.pkl"))
email_tfidf = joblib.load(os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl"))

sms_model = joblib.load(os.path.join(MODEL_DIR, "sms_spam_model.pkl"))
sms_tfidf = joblib.load(os.path.join(MODEL_DIR, "sms_tfidf_vectorizer.pkl"))

# ----------------------------------------
# FastAPI App
# ----------------------------------------
app = FastAPI(
    title="Phishing Awareness API",
    description="URL, Email, SMS Phishing Detection Backend",
    version="1.0"
)

# ----------------------------------------
# Request Models
# ----------------------------------------
class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    email_text: str

class SMSRequest(BaseModel):
    sms_text: str

# ----------------------------------------
# Health Check
# ----------------------------------------
@app.get("/")
def home():
    return {"message": "Phishing API is running successfully!"}

# ----------------------------------------
# URL Prediction
# ----------------------------------------
@app.post("/predict/url")
def predict_url(data: URLRequest):
    url = data.url
    prediction = url_model.predict([url])[0]

    return {
        "url": url,
        "prediction": int(prediction),
        "label": "safe" if prediction == 0 else "phishing"
    }

# ----------------------------------------
# Email Prediction
# ----------------------------------------
@app.post("/predict/email")
def predict_email(data: EmailRequest):
    text = data.email_text

    vector = email_tfidf.transform([text])
    prediction = email_model.predict(vector)[0]

    return {
        "prediction": int(prediction),
        "label": "safe" if prediction == 0 else "phishing"
    }

# ----------------------------------------
# SMS Prediction
# ----------------------------------------
@app.post("/predict/sms")
def predict_sms(data: SMSRequest):
    text = data.sms_text

    vector = sms_tfidf.transform([text])
    prediction = sms_model.predict(vector)[0]

    return {
        "prediction": int(prediction),
        "label": "safe" if prediction == 0 else "spam"
    }

# ----------------------------------------
# Run
# ----------------------------------------
if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
