from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from models import User

users_bp = Blueprint("users", __name__)


@users_bp.get("/by-email")
@jwt_required()
def by_email():
    email = request.args.get("email", "").strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(error="Account not found"), 404
    return jsonify(id=user.id, email=user.email, public_key=user.public_key)
