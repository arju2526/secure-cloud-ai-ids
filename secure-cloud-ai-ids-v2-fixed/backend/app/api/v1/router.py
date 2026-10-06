from fastapi import APIRouter
from app.api import auth, detection

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth")
api_router.include_router(detection.router, prefix="/detection")
