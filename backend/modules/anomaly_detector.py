from datetime import timedelta

from models import DownloadEvent, db, utcnow


def record_download(user_id, file_id, window_seconds, threshold):
    """Record a download event and indicate whether the burst threshold was met."""
    now = utcnow()
    cutoff = now - timedelta(seconds=window_seconds)
    DownloadEvent.query.filter(
        DownloadEvent.user_id == user_id,
        DownloadEvent.created_at < cutoff,
    ).delete(synchronize_session=False)
    count = DownloadEvent.query.filter(
        DownloadEvent.user_id == user_id,
        DownloadEvent.created_at >= cutoff,
    ).count() + 1
    db.session.add(DownloadEvent(user_id=user_id, file_id=file_id, created_at=now))
    return count >= threshold, count
