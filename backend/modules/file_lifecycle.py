from datetime import timezone
from pathlib import Path

from models import FileShare, SecureFile, db, utcnow


def is_expired(secure_file):
    expires_at = secure_file.expires_at
    if expires_at is None:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= utcnow()


def delete_file_data(secure_file, storage_dir):
    path = Path(storage_dir) / secure_file.storage_name
    if path.exists():
        path.unlink()
    FileShare.query.filter_by(file_id=secure_file.id).delete()
    db.session.delete(secure_file)


def remove_expired(storage_dir):
    expired = [item for item in SecureFile.query.all() if is_expired(item)]
    for item in expired:
        delete_file_data(item, storage_dir)
    if expired:
        db.session.commit()
