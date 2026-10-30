import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from app import create_app
from models import db


@pytest.fixture()
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "JWT_SECRET_KEY": "test-jwt-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
        "UPLOAD_FOLDER": str(tmp_path / "uploads"),
        "CORS_ORIGINS": ["http://localhost:5173"],
        "ANOMALY_WINDOW_SECONDS": 60,
        "ANOMALY_DOWNLOAD_THRESHOLD": 2,
    })
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()
