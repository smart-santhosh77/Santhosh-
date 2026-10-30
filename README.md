# VaultShare — Secure File Sharing

A final-year engineering cybersecurity project demonstrating authenticated file sharing with browser-side encryption, recipient key wrapping, expiring/self-destructing files, download anomaly signals, and optional Ethereum-compatible integrity proofs.

## Security design

- Before upload, the browser encrypts file bytes with AES-256-GCM and wraps that file key for the owner using RSA-OAEP. The server stores ciphertext and wrapped keys only.
- Every account gets an RSA-3072 keypair generated in the browser. Its private key is encrypted with AES-GCM using a PBKDF2-SHA-256 password-derived key and a random salt. Flask stores the public key and encrypted private-key envelope, not an unwrapped private key or file key.
- Sharing re-wraps the file key for a recipient's public key. Authentication, ownership, share grants/revocation, and file access are checked by Flask on every request.
- File expiry and optional download limits remove the server-side ciphertext. A burst of downloads emits a visible heuristic anomaly signal; it does not block users.
- The optional blockchain registry stores a SHA-256 digest of ciphertext, not file contents. It is useful for an integrity demonstration, not proof of authorship, confidentiality, or availability.

This is a local-development educational prototype, not production-ready software. File names, account identity, file sizes, share relationships, and access timing are visible to the server. HTTPS is required outside localhost. A browser or endpoint compromise, malicious frontend, weak password, screenshots, downloaded copies, browser caches, or an already-obtained key are outside this model. “Self-destruct” cannot revoke or erase copies a recipient already downloaded.

## Phase overview

1. **Core app:** Flask API with registration/login, upload/download, relational metadata, and React dashboard.
2. **Zero knowledge:** Web Crypto encryption/decryption in the browser before bytes reach Flask; password-encrypted account private keys and per-recipient RSA-wrapped file keys.
3. **Blockchain:** Solidity `FileRegistry`, Truffle migration, and optional ethers wallet transaction to record ciphertext hashes on local Ganache.
4. **Advanced controls:** expiry and atomic download-count deletion, share revocation, per-account download-burst anomaly signal, and API/UI integration.

## Local quick start

Requirements: Python 3.11+, Node.js 20+, npm. Optional blockchain setup needs Truffle and Ganache.

1. Copy `.env.example` to `.env`; set `SECRET_KEY` to a unique random value. Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`.
2. Run the Flask API from the repository root:

   ```sh
   python -m venv .venv
   # Windows: .venv\Scripts\activate
   # macOS/Linux: source .venv/bin/activate
   pip install -r backend/requirements-dev.txt
   python backend/app.py
   ```

3. In another terminal:

   ```sh
   cd frontend
   npm install
   npm run dev
   ```

4. Open `http://localhost:5173`, register an account (password minimum 12 characters), then upload. Register a second account to try sharing. The backend listens at `http://localhost:5000`.

The API loads the repository-root `.env`, creates its SQLite database and ciphertext directory on first run, and requires `SECRET_KEY`. The frontend keeps its access token in session storage and the unlocked private key in memory only; a page reload requires the password again.

### Docker Compose

After setting `SECRET_KEY` in `.env`, start the local-development services with:

```sh
docker compose up --build
```

Visit the Vite app at `http://localhost:5173`. SQLite and encrypted uploads use a persistent Docker volume. The included frontend container runs the Vite development server and must not be exposed as a production web deployment.

## Optional local blockchain

Run a local Ganache development chain at `127.0.0.1:8545` with chain ID `1337`, then deploy:

```sh
cd blockchain
npm install
npm run migrate
```

Set `BLOCKCHAIN_REGISTRY_ADDRESS` in the repository-root `.env` to the deployed `FileRegistry` address and restart Flask. Connect a wallet configured for the Ganache chain. The **Proof** action submits a user-paid wallet transaction with the current ciphertext SHA-256 digest. Without a registry, wallet, or local chain, file sharing remains available and proofs are disabled.

## Test and build

```sh
python -m pip install -r backend/requirements-dev.txt
python -m pytest backend/tests
cd frontend
npm install
npm run test:crypto
npm run build
cd ../blockchain
npm test
```

## Configuration and further documentation

See [SETUP.md](SETUP.md) for API routes, multipart fields, environment variables, and key/deletion semantics. `.env.example` contains placeholders only.

Before any real deployment, replace local SQLite and disk storage with managed database/private object storage, enforce HTTPS and strict CORS, add rate limiting, monitoring and safe backups, design key recovery/rotation, review dependencies, threat-model the full system, and operate it behind a hardened production server. Do not expose Ganache or development wallets to the internet.

The frontend production dependency audit reports no advisories in the current install. Truffle is a legacy development toolchain and its transitive development dependencies report npm audit advisories; keep it isolated to local contract development and do not deploy its tooling or Ganache as application services.
