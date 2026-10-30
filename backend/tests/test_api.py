import base64
import hashlib
import io
from datetime import timedelta
from pathlib import Path

from models import SecureFile, db, utcnow


def register(client, email):
    response = client.post("/api/auth/register", json={
        "email": email,
        "password": "correct horse battery",
        "public_key": base64.b64encode(b"test-public-key").decode(),
        "key_salt": base64.b64encode(b"0123456789abcdef").decode(),
        "encrypted_private_key": (
            base64.b64encode(b"123456789012").decode()
            + "."
            + base64.b64encode(b"encrypted-private-key-placeholder").decode()
        ),
    })
    assert response.status_code == 201
    return response.get_json()["access_token"]


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def upload(client, token, name="hello.txt", max_downloads=None):
    data = {
        "file": (io.BytesIO(b"ciphertext bytes"), name),
        "wrapped_key": base64.b64encode(b"opaque-wrapped-key").decode(),
    }
    if max_downloads is not None:
        data["max_downloads"] = str(max_downloads)
    response = client.post("/api/files", headers=headers(token), data=data, content_type="multipart/form-data")
    assert response.status_code == 201, response.get_json()
    return response.get_json()["file"]


def test_authentication_and_password_minimum(client):
    response = client.post("/api/auth/register", json={
        "email": "weak@example.test",
        "password": "short",
        "public_key": "public",
        "key_salt": "salt",
        "encrypted_private_key": "private",
    })
    assert response.status_code == 400
    response = client.post("/api/auth/register", json={
        "email": "malformed@example.test",
        "password": "long enough password",
        "public_key": "not-base64",
        "key_salt": "c2FsdA==",
        "encrypted_private_key": "dGVzdA==",
    })
    assert response.status_code == 400
    token = register(client, "owner@example.test")
    assert client.get("/api/auth/me", headers=headers(token)).status_code == 200
    assert client.post("/api/auth/login", json={
        "email": "owner@example.test",
        "password": "wrong password value",
    }).status_code == 401


def test_file_ciphertext_access_and_share_revocation(client):
    owner = register(client, "owner@example.test")
    recipient = register(client, "recipient@example.test")
    outsider = register(client, "outsider@example.test")
    item = upload(client, owner)
    file_path = Path(client.application.config["UPLOAD_FOLDER"]) / item["id"]
    assert file_path.read_bytes() == b"ciphertext bytes"
    assert item["ciphertext_hash"] == hashlib.sha256(b"ciphertext bytes").hexdigest()
    assert client.get(f"/api/files/{item['id']}", headers=headers(outsider)).status_code == 403

    response = client.post(
        f"/api/files/{item['id']}/shares",
        headers=headers(owner),
        json={"email": "recipient@example.test", "wrapped_key": base64.b64encode(b"recipient-key").decode()},
    )
    assert response.status_code == 201
    shared = client.get("/api/files", headers=headers(recipient)).get_json()["files"]
    assert len(shared) == 1
    assert shared[0]["wrapped_key"] == base64.b64encode(b"recipient-key").decode()
    assert client.get(f"/api/files/{item['id']}", headers=headers(recipient)).data == b"ciphertext bytes"

    share_id = client.get(f"/api/files/{item['id']}/shares", headers=headers(owner)).get_json()["shares"][0]["id"]
    assert client.delete(f"/api/files/{item['id']}/shares/{share_id}", headers=headers(owner)).status_code == 204
    assert client.get(f"/api/files/{item['id']}", headers=headers(recipient)).status_code == 403


def test_download_limit_self_destructs_server_ciphertext(client, app):
    token = register(client, "limited@example.test")
    item = upload(client, token, max_downloads=1)
    path = Path(app.config["UPLOAD_FOLDER"]) / item["id"]
    response = client.get(f"/api/files/{item['id']}", headers=headers(token))
    assert response.status_code == 200
    assert response.data == b"ciphertext bytes"
    assert not path.exists()
    assert client.get(f"/api/files/{item['id']}", headers=headers(token)).status_code == 404


def test_download_burst_is_exposed_as_anomaly_signal(client):
    token = register(client, "watch@example.test")
    item = upload(client, token)
    first = client.get(f"/api/files/{item['id']}", headers=headers(token))
    second = client.get(f"/api/files/{item['id']}", headers=headers(token))
    assert first.headers["X-Download-Anomaly"] == "false"
    assert second.headers["X-Download-Anomaly"] == "true"
    assert second.headers["X-Recent-Downloads"] == "2"


def test_invalid_ids_and_non_owner_delete_are_rejected(client):
    owner = register(client, "delete-owner@example.test")
    other = register(client, "delete-other@example.test")
    item = upload(client, owner)
    assert client.get("/api/files/not-a-uuid", headers=headers(owner)).status_code == 404
    assert client.delete(f"/api/files/{item['id']}", headers=headers(other)).status_code == 403
    with client.application.app_context():
        assert db.session.get(SecureFile, item["id"]) is not None


def test_expired_file_is_removed_when_api_is_accessed(client, app):
    token = register(client, "expiry@example.test")
    item = upload(client, token)
    with app.app_context():
        secure_file = db.session.get(SecureFile, item["id"])
        secure_file.expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
    path = Path(app.config["UPLOAD_FOLDER"]) / item["id"]
    assert path.exists()
    assert client.get("/api/files", headers=headers(token)).status_code == 200
    assert client.get(f"/api/files/{item['id']}", headers=headers(token)).status_code == 404
    assert not path.exists()
