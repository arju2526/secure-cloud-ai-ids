from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.router import api_router
from app.db.database import engine, Base
from app.models.entities import User, NetworkLog, SecurityAlert

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Cloud AI-IDS Platform API", description="Hybrid rule and AI anomaly detection backend", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/health")
def health_check():
    return {"status": "online", "engine": "ready", "detection": "hybrid-rule-ml"}
