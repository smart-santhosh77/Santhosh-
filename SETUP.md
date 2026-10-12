# Setup and API reference

## Environment

Copy `.env.example` to `.env`. `SECRET_KEY` is mandatory and must be a long random private value; the API intentionally refuses to start without it. `.env` is ignored by Git.

| Variable | Purpose | Default |
|---|---|---|
| `SECRET_KEY` | Flask and JWT signing secret | Required |
| `JWT_SECRET_KEY` | Optional separate JWT signing secret | `SECRET_KEY` |
| `DATABASE_URL` | SQLAlchemy database URL | Local SQLite |
| `UPLOAD_FOLDER` | Private directory for encrypted bytes | `backend/instance/uploads` |
| `CORS_ORIGINS` | Comma-separated allowed frontend origins | `http://localhost:5173` |
| `MAX_CONTENT_LENGTH` | Maximum request bytes, including multipart overhead | 52,428,800 |
| `JWT_ACCESS_TOKEN_MINUTES` | Access token lifetime | 30 |
| `ANOMALY_WINDOW_SECONDS` | Download observation window | 60 |
| `ANOMALY_DOWNLOAD_THRESHOLD` | Downloads within window that signal anomaly | 10 |
| `BLOCKCHAIN_CHAIN_ID` | Expected wallet chain | 1337 |
| `BLOCKCHAIN_REGISTRY_ADDRESS` | Deployed registry address; blank disables proofs | Blank |

The frontend accepts `VITE_API_URL` (defaults to `http://localhost:5000/api`). Vite variables are public configuration and must not contain secrets.

## API

All paths are below `/api`. Except registration, login, health, and blockchain config, requests require `Authorization: Bearer <access-token>`.

| Method | Path | Description |
|---|---|---|
| GET | `/health` | API health |
| POST | `/auth/register` | Register email/password, public key, salt, and encrypted private-key envelope |
| POST | `/auth/login` | Authenticate; return short-lived access token and encrypted key envelope |
| GET | `/auth/me` | Current account public key and encrypted key envelope |
| GET | `/users/by-email?email=...` | Look up recipient public key |
| GET | `/files` | List owned and shared files for current account |
| POST | `/files` | Upload encrypted bytes and owner's wrapped AES key |
| GET | `/files/<uuid>` | Download ciphertext if owner or active share; anomaly headers included |
| DELETE | `/files/<uuid>` | Delete server-side ciphertext (owner only) |
| POST | `/files/<uuid>/shares` | Grant recipient access using their RSA-wrapped file key |
| GET | `/files/<uuid>/shares` | List recipients (owner only) |
| DELETE | `/files/<uuid>/shares/<user_id>` | Revoke future access (owner only) |
| GET | `/blockchain/config` | Return optional registry address and expected chain ID |

Uploads use multipart fields `file` (ciphertext), `wrapped_key` (base64 owner RSA-OAEP envelope), optional `expires_at` (future ISO-8601 UTC), and optional `max_downloads` (1–100000). The original filename is visible metadata. Each file record includes the server-computed SHA-256 ciphertext digest; downloads compare the received bytes against that digest before browser decryption. Share requests are JSON with `email` and `wrapped_key`.

## Key and deletion semantics

The browser derives an AES-GCM wrapping key from the account password with PBKDF2-SHA-256, 310,000 iterations, and a per-account random salt. This encrypts the browser-generated RSA private key. AES-256-GCM encrypts file content using a fresh random key and IV per file. The server cannot decrypt those envelopes. A forgotten password means the private key and corresponding files cannot be recovered; account recovery and key rotation are intentionally not implemented.

Expiry is enforced when metadata is listed or a file is accessed, with cleanup performed by that API access. A download limit is enforced using a conditional database update; the final permitted response is sent while the server file and metadata are deleted. Cleanup is not guaranteed at the exact expiry instant when no API traffic occurs. Deletion does not affect previously downloaded copies, browser caches, or external backups.
