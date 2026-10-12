import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR.parent / ".env")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", f"sqlite:///{(BASE_DIR / 'instance' / 'secure_share.db').as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(os.getenv("JWT_ACCESS_TOKEN_MINUTES", "30")))
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(50 * 1024 * 1024)))
    UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", str(BASE_DIR / "instance" / "uploads"))
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
        if origin.strip()
    ]
    ANOMALY_WINDOW_SECONDS = int(os.getenv("ANOMALY_WINDOW_SECONDS", "60"))
    ANOMALY_DOWNLOAD_THRESHOLD = int(os.getenv("ANOMALY_DOWNLOAD_THRESHOLD", "10"))
    BLOCKCHAIN_CHAIN_ID = int(os.getenv("BLOCKCHAIN_CHAIN_ID", "1337"))
    BLOCKCHAIN_REGISTRY_ADDRESS = os.getenv("BLOCKCHAIN_REGISTRY_ADDRESS", "")
