import base64
import binascii

from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required

from models import FileShare, SecureFile, User, db
from modules.file_lifecycle import delete_file_data, is_expired

permissions_bp = Blueprint("permissions", __name__)


def owner_file(file_id):
    item = db.session.get(SecureFile, file_id)
    if item and is_expired(item):
        delete_file_data(item, current_app.config["UPLOAD_FOLDER"])
        db.session.commit()
        return None
    return item


@permissions_bp.post("/<file_id>/shares")
@jwt_required()
def create_share(file_id):
    item = owner_file(file_id)
    if not item:
        return jsonify(error="File not found or expired"), 404
    if item.owner_id != int(get_jwt_identity()):
        return jsonify(error="Only the owner can share this file"), 403
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    wrapped_key = data.get("wrapped_key", "")
    if not isinstance(wrapped_key, str) or not wrapped_key or len(wrapped_key) > 20000:
        return jsonify(error="A valid recipient-wrapped key is required"), 400
    try:
        decoded = base64.b64decode(wrapped_key, validate=True)
        if not decoded or len(decoded) > 10000:
            raise ValueError
    except (ValueError, binascii.Error):
        return jsonify(error="Wrapped key must be valid base64"), 400
    recipient = User.query.filter_by(email=email).first()
    if not recipient:
        return jsonify(error="Recipient account not found"), 404
    if recipient.id == item.owner_id:
        return jsonify(error="You already own this file"), 400
    share = FileShare.query.filter_by(file_id=item.id, user_id=recipient.id).first()
    if share:
        share.wrapped_key = wrapped_key
    else:
        db.session.add(FileShare(file_id=item.id, user_id=recipient.id, wrapped_key=wrapped_key))
    db.session.commit()
    return jsonify(message="Access granted", email=recipient.email), 201


@permissions_bp.get("/<file_id>/shares")
@jwt_required()
def list_shares(file_id):
    item = owner_file(file_id)
    if not item:
        return jsonify(error="File not found or expired"), 404
    if item.owner_id != int(get_jwt_identity()):
        return jsonify(error="Only the owner can list shares"), 403
    shares = FileShare.query.filter_by(file_id=item.id).all()
    return jsonify(shares=[{"id": share.user.id, "email": share.user.email} for share in shares])


@permissions_bp.delete("/<file_id>/shares/<int:recipient_id>")
@jwt_required()
def revoke_share(file_id, recipient_id):
    item = owner_file(file_id)
    if not item:
        return jsonify(error="File not found"), 404
    if item.owner_id != int(get_jwt_identity()):
        return jsonify(error="Only the owner can revoke access"), 403
    share = FileShare.query.filter_by(file_id=item.id, user_id=recipient_id).first()
    if not share:
        return jsonify(error="Share not found"), 404
    db.session.delete(share)
    db.session.commit()
    return "", 204
