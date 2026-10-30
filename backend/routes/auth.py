import base64
import binascii
import re

from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash, generate_password_hash

from models import User, db

auth_bp = Blueprint("auth", __name__)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def user_payload(user):
    return {
        "id": user.id,
        "email": user.email,
        "public_key": user.public_key,
        "key_salt": user.key_salt,
        "encrypted_private_key": user.encrypted_private_key,
    }


@auth_bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password")
    key_values = [
        data.get("public_key"),
        data.get("key_salt"),
        data.get("encrypted_private_key"),
    ]
    if not isinstance(password, str) or not 12 <= len(password) <= 1024:
        return jsonify(error="Password must contain 12 to 1024 characters"), 400
    if not EMAIL_RE.fullmatch(email) or len(email) > 254:
        return jsonify(error="A valid email address is required"), 400
    if not all(isinstance(value, str) and value and len(value) <= 20000 for value in key_values):
        return jsonify(error="A valid encrypted key envelope is required"), 400
    try:
        public_key = base64.b64decode(key_values[0], validate=True)
        salt = base64.b64decode(key_values[1], validate=True)
        iv_text, private_text = key_values[2].split(".", maxsplit=1)
        iv = base64.b64decode(iv_text, validate=True)
        encrypted_private = base64.b64decode(private_text, validate=True)
        if not 1 <= len(public_key) <= 4096 or len(salt) != 16 or len(iv) != 12:
            raise ValueError
        if not 16 <= len(encrypted_private) <= 10000:
            raise ValueError
    except (ValueError, binascii.Error):
        return jsonify(error="Public key or encrypted private-key envelope is malformed"), 400
    if User.query.filter_by(email=email).first():
        return jsonify(error="An account with that email already exists"), 409
    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        public_key=key_values[0],
        key_salt=key_values[1],
        encrypted_private_key=key_values[2],
    )
    db.session.add(user)
    db.session.commit()
    return jsonify(access_token=create_access_token(identity=str(user.id)), user=user_payload(user)), 201


@auth_bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = data.get("password")
    user = User.query.filter_by(email=email).first()
    if not user or not isinstance(password, str) or not check_password_hash(user.password_hash, password):
        return jsonify(error="Invalid email or password"), 401
    return jsonify(access_token=create_access_token(identity=str(user.id)), user=user_payload(user))


@auth_bp.get("/me")
@jwt_required()
def me():
    user = db.session.get(User, int(get_jwt_identity()))
    if not user:
        return jsonify(error="Account not found"), 404
    return jsonify(user=user_payload(user))
