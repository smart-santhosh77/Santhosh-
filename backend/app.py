from pathlib import Path

from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from sqlalchemy.exc import IntegrityError

from config import Config
from models import db
from routes.auth import auth_bp
from routes.blockchain import blockchain_bp
from routes.files import files_bp
from routes.permissions import permissions_bp
from routes.users import users_bp


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("Set SECRET_KEY in the environment or .env file before starting the API")
    if not app.config.get("JWT_SECRET_KEY"):
        app.config["JWT_SECRET_KEY"] = app.config["SECRET_KEY"]
    Path(app.config["UPLOAD_FOLDER"]).mkdir(parents=True, exist_ok=True)
    db.init_app(app)
    JWTManager(app)
    CORS(app, resources={r"/api/*": {"origins": app.config["CORS_ORIGINS"]}})

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(users_bp, url_prefix="/api/users")
    app.register_blueprint(files_bp, url_prefix="/api/files")
    app.register_blueprint(permissions_bp, url_prefix="/api/files")
    app.register_blueprint(blockchain_bp, url_prefix="/api/blockchain")

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    @app.errorhandler(IntegrityError)
    def handle_integrity_error(_error):
        db.session.rollback()
        return jsonify(error="The requested change conflicts with existing data"), 409

    @app.errorhandler(413)
    def payload_too_large(_error):
        return jsonify(error="Request exceeds the configured size limit"), 413

    with app.app_context():
        db.create_all()
    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
