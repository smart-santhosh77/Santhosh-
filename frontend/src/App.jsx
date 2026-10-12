import { useCallback, useEffect, useState } from "react";
import { api, jsonApi, getToken } from "./api";
import {
  createAccountKeys,
  decryptFile,
  encryptFile,
  rewrapFileKey,
  sha256Hex,
  unlockPrivateKey,
} from "./crypto";

const registryAbi = [
  "function recordHash(bytes32 digest, string calldata fileId)",
  "event FileHashRecorded(bytes32 indexed digest, string fileId, address indexed reporter, uint256 timestamp)",
];

function App() {
  const [account, setAccount] = useState(null);
  const [privateKey, setPrivateKey] = useState(null);
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState("login");
  const [files, setFiles] = useState([]);
  const [shareReload, setShareReload] = useState(0);
  const [blockchain, setBlockchain] = useState({ enabled: false });
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const refreshFiles = useCallback(async () => {
    const data = await jsonApi("/files");
    setFiles(data.files);
  }, []);

  useEffect(() => {
    jsonApi("/blockchain/config").then(setBlockchain).catch(() => {});
    if (!getToken()) return;
    jsonApi("/auth/me")
      .then(({ user }) => setAccount(user))
      .catch(() => sessionStorage.removeItem("access_token"));
  }, []);

  useEffect(() => {
    if (account) refreshFiles().catch((reason) => setError(reason.message));
  }, [account, refreshFiles]);

  const clearNotices = () => {
    setError("");
    setMessage("");
  };

  async function authenticate(event) {
    event.preventDefault();
    clearNotices();
    const email = event.currentTarget.email.value;
    setBusy("auth");
    try {
      let data;
      if (mode === "register") {
        const keyData = await createAccountKeys(password);
        data = await jsonApi("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email, password, ...keyData }),
        });
      } else {
        data = await jsonApi("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email, password }),
        });
      }
      const unlocked = await unlockPrivateKey(data.user, password);
      sessionStorage.setItem("access_token", data.access_token);
      setAccount(data.user);
      setPrivateKey(unlocked);
      setPassword("");
      setMessage(mode === "register" ? "Account and encrypted keypair created." : "Signed in and unlocked.");
    } catch (reason) {
      setError(reason.message);
    } finally {
      setBusy("");
    }
  }

  async function unlock(event) {
    event.preventDefault();
    clearNotices();
    setBusy("unlock");
    try {
      const unlocked = await unlockPrivateKey(account, password);
      setPrivateKey(unlocked);
      setPassword("");
      setMessage("Private key unlocked in this browser session.");
    } catch (reason) {
      setError(reason.message);
    } finally {
      setBusy("");
    }
  }

  function signOut() {
    sessionStorage.removeItem("access_token");
    setAccount(null);
    setPrivateKey(null);
    setFiles([]);
    setPassword("");
    clearNotices();
  }

  async function upload(event) {
    event.preventDefault();
    clearNotices();
    const form = event.currentTarget;
    const selected = form.file.files[0];
    if (!selected || !privateKey) return;
    setBusy("upload");
    try {
      const { blob, wrappedKey } = await encryptFile(selected, account.public_key);
      const body = new FormData();
      body.append("file", blob, selected.name);
      body.append("wrapped_key", wrappedKey);
      if (form.expires_at.value) body.append("expires_at", new Date(form.expires_at.value).toISOString());
      if (form.max_downloads.value) body.append("max_downloads", form.max_downloads.value);
      await jsonApi("/files", { method: "POST", body });
      form.reset();
      setMessage(`Encrypted ${selected.name} in your browser and uploaded the ciphertext.`);
      await refreshFiles();
    } catch (reason) {
      setError(reason.message);
    } finally {
      setBusy("");
    }
  }

  async function download(item) {
    clearNotices();
    if (!privateKey) return setError("Unlock your key before decrypting files.");
    setBusy(`download:${item.id}`);
    try {
      const response = await api(`/files/${item.id}`);
      const ciphertext = await response.blob();
      if (await sha256Hex(ciphertext) !== item.ciphertext_hash) {
        throw new Error("Ciphertext hash does not match the server's recorded upload digest.");
      }
      await decryptFile(await ciphertext.arrayBuffer(), privateKey, item.wrapped_key, item.name);
      if (response.headers.get("X-Download-Anomaly") === "true") {
        setMessage(`Download completed. Security signal: ${response.headers.get("X-Recent-Downloads")} recent downloads in the configured window.`);
      } else {
        setMessage(`Decrypted ${item.name} locally. Server-side ciphertext is retained unless its expiry or download limit was reached.`);
      }
      await refreshFiles();
    } catch (reason) {
      setError(reason.message);
    } finally {
      setBusy("");
    }
  }

  async function share(item, event) {
    event.preventDefault();
    clearNotices();
    if (!privateKey) return setError("Unlock your key before sharing.");
    const form = event.currentTarget;
    const email = form.email.value.trim();
    setBusy(`share:${item.id}`);
    try {
      const recipient = await jsonApi(`/users/by-email?email=${encodeURIComponent(email)}`);
      const wrappedKey = await rewrapFileKey(privateKey, item.wrapped_key, recipient.public_key);
      await jsonApi(`/files/${item.id}/shares`, {
        method: "POST",
        body: JSON.stringify({ email, wrapped_key: wrappedKey }),
      });
      form.reset();
      setMessage(`Access granted to ${recipient.email}. Revoking access cannot erase keys or copies already obtained.`);
      setShareReload((value) => value + 1);
      await refreshFiles();
    } catch (reason) {
      setError(reason.message);
    } finally {
      setBusy("");
    }
  }

  async function revoke(item, recipientId) {
    clearNotices();
    try {
      await api(`/files/${item.id}/shares/${recipientId}`, { method: "DELETE" });
      setMessage("Share revoked for future server downloads.");
      setShareReload((value) => value + 1);
      await refreshFiles();
    } catch (reason) {
      setError(reason.message);
    }
  }

  async function deleteFile(item) {
    if (!window.confirm(`Permanently delete server-side ciphertext for “${item.name}”? Existing copies cannot be recalled.`)) return;
    clearNotices();
    try {
      await api(`/files/${item.id}`, { method: "DELETE" });
      setMessage("Server-side ciphertext deleted.");
      await refreshFiles();
    } catch (reason) {
      setError(reason.message);
    }
  }

  async function recordProof(item) {
    clearNotices();
    setBusy(`proof:${item.id}`);
    try {
      if (!blockchain.enabled || !window.ethereum) throw new Error("Configure a registry address and connect a wallet provider.");
      const { BrowserProvider, Contract } = await import("ethers");
      const provider = new BrowserProvider(window.ethereum);
      await provider.send("eth_requestAccounts", []);
      const network = await provider.getNetwork();
      if (Number(network.chainId) !== Number(blockchain.chain_id)) {
        throw new Error(`Switch your wallet to chain ${blockchain.chain_id} before recording a proof.`);
      }
      const digest = `0x${item.ciphertext_hash}`;
      const signer = await provider.getSigner();
      const registry = new Contract(blockchain.registry_address, registryAbi, signer);
      const transaction = await registry.recordHash(digest, item.id);
      await transaction.wait();
      setMessage(`Ciphertext integrity hash recorded on-chain (${transaction.hash}).`);
    } catch (reason) {
      setError(reason.message);
    } finally {
      setBusy("");
    }
  }

  if (!account) {
    return (
      <main className="auth-shell">
        <section className="auth-card">
          <div className="brand-mark">V</div>
          <p className="eyebrow">CLIENT-SIDE ENCRYPTED STORAGE</p>
          <h1>VaultShare</h1>
          <p className="muted">Share files without handing the server your decryption key.</p>
          <Notice error={error} message={message} />
          <form className="stack" onSubmit={authenticate}>
            <label>Email<input name="email" type="email" autoComplete="email" required /></label>
            <label>Password<input type="password" autoComplete={mode === "register" ? "new-password" : "current-password"} minLength="12" value={password} onChange={(event) => setPassword(event.target.value)} required /></label>
            {mode === "register" && <p className="hint">Use at least 12 characters. Your password encrypts your private key; forgetting it means files cannot be recovered.</p>}
            <button className="primary" disabled={busy === "auth"}>{busy === "auth" ? "Working…" : mode === "register" ? "Create account" : "Sign in"}</button>
          </form>
          <button className="text-button" onClick={() => { setMode(mode === "login" ? "register" : "login"); setPassword(""); clearNotices(); }}>
            {mode === "login" ? "New here? Create an account" : "Already registered? Sign in"}
          </button>
        </section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="#"><span className="brand-mark small">V</span> VaultShare</a>
        <div className="user-menu"><span>{account.email}</span><button className="secondary" onClick={signOut}>Sign out</button></div>
      </header>
      <section className="hero">
        <div><p className="eyebrow">PRIVATE BY DESIGN</p><h1>Your files, your keys.</h1>
          <p className="muted">Files are encrypted in this browser before upload. The server stores ciphertext and wrapped keys.</p></div>
        <div className="security-chip"><span className="pulse" /> AES-256-GCM · RSA-OAEP</div>
      </section>
      <Notice error={error} message={message} />
      {!privateKey ? (
        <section className="panel unlock-panel">
          <div><p className="eyebrow">BROWSER KEY LOCKED</p><h2>Unlock your private key</h2><p className="muted">Enter your account password. The key is decrypted locally and kept in memory for this session.</p></div>
          <form className="unlock-form" onSubmit={unlock}>
            <input type="password" autoComplete="current-password" minLength="12" placeholder="Account password" value={password} onChange={(event) => setPassword(event.target.value)} required />
            <button className="primary" disabled={busy === "unlock"}>{busy === "unlock" ? "Unlocking…" : "Unlock key"}</button>
          </form>
        </section>
      ) : (
        <section className="dashboard-grid">
          <section className="panel upload-panel">
            <div className="panel-heading"><div><p className="eyebrow">NEW SECURE SHARE</p><h2>Encrypt & upload</h2></div><span className="step-number">01</span></div>
            <form className="stack" onSubmit={upload}>
              <label className="file-picker">Choose a file<input name="file" type="file" required /><span>Select a file from this device</span><small>Encryption happens before data leaves your browser.</small></label>
              <div className="form-row">
                <label>Expires at <span className="optional">optional</span><input name="expires_at" type="datetime-local" /></label>
                <label>Download limit <span className="optional">optional</span><input name="max_downloads" type="number" min="1" max="100000" placeholder="Unlimited" /></label>
              </div>
              <button className="primary" disabled={busy === "upload"}>{busy === "upload" ? "Encrypting & uploading…" : "Encrypt and upload"}</button>
            </form>
            <p className="hint">Expiry and download limits delete the server copy only. Recipients may keep files they already downloaded.</p>
          </section>
          <section className="panel files-panel">
            <div className="panel-heading"><div><p className="eyebrow">YOUR VAULT</p><h2>Shared files <span className="count">{files.length}</span></h2></div><button className="secondary" onClick={() => refreshFiles().catch((reason) => setError(reason.message))}>Refresh</button></div>
            {files.length === 0 ? <div className="empty-state"><div className="empty-icon">▤</div><strong>Your vault is empty</strong><span>Encrypt and upload a file to get started.</span></div> :
              <div className="file-list">{files.map((item) => (
                <article className="file-card" key={item.id}>
                  <div className="file-icon">▧</div>
                  <div className="file-info"><div className="file-title">{item.name}<span className={item.is_owner ? "badge owner" : "badge shared"}>{item.is_owner ? "Owner" : "Shared with you"}</span></div>
                    <div className="file-meta">{formatBytes(item.size_bytes)} · {item.is_owner ? "you" : `from ${item.owner_email}`} · {item.download_count}{item.max_downloads ? `/${item.max_downloads} downloads` : " downloads"}{item.expires_at ? ` · expires ${new Date(item.expires_at).toLocaleString()}` : ""}</div>
                  </div>
                  <div className="file-actions">
                    <button className="primary compact" disabled={busy === `download:${item.id}`} onClick={() => download(item)}>{busy === `download:${item.id}` ? "…" : "Decrypt"}</button>
                    {item.is_owner && <button className="secondary compact" disabled={busy === `proof:${item.id}`} title={blockchain.enabled ? "Record ciphertext hash on configured blockchain" : "Blockchain registry is not configured"} onClick={() => recordProof(item)}>{busy === `proof:${item.id}` ? "…" : "Proof"}</button>}
                    {item.is_owner && <button className="danger compact" onClick={() => deleteFile(item)}>Delete</button>}
                  </div>
                  {item.is_owner && <div className="share-row">
                    <form onSubmit={(event) => share(item, event)}><input name="email" type="email" placeholder="Recipient account email" required /><button className="secondary compact" disabled={busy === `share:${item.id}`}>{busy === `share:${item.id}` ? "Sharing…" : "Share"}</button></form>
                    <ShareList item={item} onRevoke={revoke} reload={shareReload} />
                  </div>}
                </article>
              ))}</div>}
          </section>
        </section>
      )}
      <section className="disclaimer"><strong>Prototype security note</strong><span>Metadata is visible to the server. Revoking access cannot erase plaintext or keys already obtained. Anomaly alerts are heuristic, not account blocks. Blockchain proofs record hashes, not file contents.</span></section>
    </main>
  );
}

function ShareList({ item, onRevoke, reload }) {
  const [shares, setShares] = useState([]);
  const [error, setError] = useState("");
  useEffect(() => {
    jsonApi(`/files/${item.id}/shares`).then((data) => setShares(data.shares)).catch((reason) => setError(reason.message));
  }, [item.id, reload]);
  if (error) return <span className="share-list-error">{error}</span>;
  if (shares.length === 0) return <span className="share-placeholder">No recipients yet</span>;
  return <div className="share-list">{shares.map((share) => <span className="recipient" key={share.id}>{share.email}<button aria-label={`Revoke ${share.email}`} onClick={() => onRevoke(item, share.id)}>×</button></span>)}</div>;
}

function Notice({ error, message }) {
  if (!error && !message) return null;
  return <div className={`notice ${error ? "notice-error" : "notice-success"}`} role="status">{error || message}</div>;
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

export default App;
