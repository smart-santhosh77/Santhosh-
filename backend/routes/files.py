import base64
import binascii
import hashlib
import io
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request, send_file
from flask_jwt_extended import get_jwt_identity, jwt_required
from sqlalchemy import update
from werkzeug.utils import secure_filename

from models import FileShare, SecureFile, User, db
from modules.anomaly_detector import record_download
from modules.file_lifecycle import delete_file_data, is_expired, remove_expired

files_bp = Blueprint("files", __name__)
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def current_user():
    return db.session.get(User, int(get_jwt_identity()))


def file_payload(item, user_id):
    share = FileShare.query.filter_by(file_id=item.id, user_id=user_id).first()
    return {
        "id": item.id,
        "name": item.original_name,
        "size_bytes": item.size_bytes,
        "ciphertext_hash": item.ciphertext_hash,
        "created_at": item.created_at.isoformat(),
        "expires_at": item.expires_at.isoformat() if item.expires_at else None,
        "max_downloads": item.max_downloads,
        "download_count": item.download_count,
        "owner_email": item.owner.email,
        "is_owner": item.owner_id == user_id,
        "wrapped_key": item.wrapped_key if item.owner_id == user_id else share.wrapped_key,
    }


def active_file(file_id):
    if not UUID_RE.fullmatch(file_id):
        return None
    item = db.session.get(SecureFile, file_id)
    if item and is_expired(item):
        delete_file_data(item, current_app.config["UPLOAD_FOLDER"])
        db.session.commit()
        return None
    return item


@files_bp.get("")
@jwt_required()
def list_files():
    remove_expired(current_app.config["UPLOAD_FOLDER"])
    user = current_user()
    owned = SecureFile.query.filter_by(owner_id=user.id).all()
    shares = FileShare.query.filter_by(user_id=user.id).all()
    items = {item.id: item for item in owned}
    for share in shares:
        item = db.session.get(SecureFile, share.file_id)
        if item:
            items[item.id] = item
    return jsonify(files=[file_payload(item, user.id) for item in items.values()])


@files_bp.post("")
@jwt_required()
def upload_file():
    user = current_user()
    uploaded = request.files.get("file")
    wrapped_key = request.form.get("wrapped_key", "")
    if not uploaded or not uploaded.filename:
        return jsonify(error="Encrypted file is required"), 400
    if not wrapped_key or len(wrapped_key) > 20000:
        return jsonify(error="A valid owner-wrapped key is required"), 400
    try:
        decoded_key = base64.b64decode(wrapped_key, validate=True)
        if not decoded_key or len(decoded_key) > 10000:
            raise ValueError
    except (ValueError, binascii.Error):
        return jsonify(error="Wrapped key must be valid base64"), 400

    filename = secure_filename(Path(uploaded.filename).name)[:255] or "encrypted-file"
    expires_at = None
    expires_value = request.form.get("expires_at", "").strip()
    if expires_value:
        try:
            expires_at = datetime.fromisoformat(expires_value.replace("Z", "+00:00"))
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= datetime.now(timezone.utc):
                raise ValueError
        except ValueError:
            return jsonify(error="Expiry must be a future ISO-8601 date"), 400

    max_downloads = None
    max_value = request.form.get("max_downloads", "").strip()
    if max_value:
        try:
            max_downloads = int(max_value)
            if not 1 <= max_downloads <= 100000:
                raise ValueError
        except ValueError:
            return jsonify(error="Download limit must be between 1 and 100000"), 400

    storage_name = str(uuid.uuid4())
    storage_dir = Path(current_app.config["UPLOAD_FOLDER"])
    storage_dir.mkdir(parents=True, exist_ok=True)
    target = storage_dir / storage_name
    uploaded.save(target)
    item = SecureFile(
        id=storage_name,
        owner_id=user.id,
        original_name=filename,
        storage_name=storage_name,
        wrapped_key=wrapped_key,
        size_bytes=target.stat().st_size,
        ciphertext_hash=hashlib.sha256(target.read_bytes()).hexdigest(),
        expires_at=expires_at,
        max_downloads=max_downloads,
    )
    db.session.add(item)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        target.unlink(missing_ok=True)
        raise
    return jsonify(file=file_payload(item, user.id)), 201


@files_bp.get("/<file_id>")
@jwt_required()
def download_file(file_id):
    user = current_user()
    item = active_file(file_id)
    if not item:
        return jsonify(error="File not found or expired"), 404
    share = FileShare.query.filter_by(file_id=item.id, user_id=user.id).first()
    if item.owner_id != user.id and not share:
        return jsonify(error="You do not have access to this file"), 403
    path = Path(current_app.config["UPLOAD_FOLDER"]) / item.storage_name
    if not path.is_file():
        return jsonify(error="Stored file is unavailable"), 500
    ciphertext = path.read_bytes()
    prior_download_count = item.download_count
    anomaly, count = record_download(
        user.id, item.id, current_app.config["ANOMALY_WINDOW_SECONDS"],
        current_app.config["ANOMALY_DOWNLOAD_THRESHOLD"],
    )
    result = db.session.execute(
        update(SecureFile)
        .where(
            SecureFile.id == item.id,
            (SecureFile.max_downloads.is_(None))
            | (SecureFile.download_count < SecureFile.max_downloads),
        )
        .values(download_count=SecureFile.download_count + 1)
    )
    if result.rowcount != 1:
        db.session.rollback()
        return jsonify(error="Download limit reached"), 410
    if item.max_downloads is not None and prior_download_count + 1 >= item.max_downloads:
        delete_file_data(item, current_app.config["UPLOAD_FOLDER"])
    db.session.commit()
    response = send_file(
        io.BytesIO(ciphertext), mimetype="application/octet-stream", as_attachment=True,
        download_name="encrypted.bin", max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Download-Anomaly"] = "true" if anomaly else "false"
    response.headers["X-Recent-Downloads"] = str(count)
    return response


@files_bp.delete("/<file_id>")
@jwt_required()
def delete_file(file_id):
    user = current_user()
    item = active_file(file_id)
    if not item:
        return jsonify(error="File not found"), 404
    if item.owner_id != user.id:
        return jsonify(error="Only the owner can delete this file"), 403
    delete_file_data(item, current_app.config["UPLOAD_FOLDER"])
    db.session.commit()
    return "", 204
