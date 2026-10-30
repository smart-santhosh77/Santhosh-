const encoder = new TextEncoder();
const decoder = new TextDecoder();
const PBKDF2_ITERATIONS = 310000;

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

async function passwordKey(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function createAccountKeys(password) {
  const pair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await passwordKey(password, salt);
  const privateBytes = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  const encryptedPrivate = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, privateBytes);
  const publicBytes = await crypto.subtle.exportKey("spki", pair.publicKey);
  return {
    public_key: toBase64(new Uint8Array(publicBytes)),
    key_salt: toBase64(salt),
    encrypted_private_key: `${toBase64(iv)}.${toBase64(new Uint8Array(encryptedPrivate))}`,
  };
}

export async function unlockPrivateKey(account, password) {
  const [ivText, encryptedText] = account.encrypted_private_key.split(".");
  if (!ivText || !encryptedText) throw new Error("The stored private-key envelope is invalid.");
  const wrappingKey = await passwordKey(password, fromBase64(account.key_salt));
  let privateBytes;
  try {
    privateBytes = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(ivText) },
      wrappingKey,
      fromBase64(encryptedText),
    );
  } catch {
    throw new Error("Could not unlock your private key. Check your password.");
  }
  return crypto.subtle.importKey(
    "pkcs8",
    privateBytes,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
}

async function importPublicKey(encoded) {
  return crypto.subtle.importKey(
    "spki",
    fromBase64(encoded),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
}

export async function encryptFile(file, ownerPublicKey) {
  const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = await file.arrayBuffer();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);
  const rawKey = await crypto.subtle.exportKey("raw", aesKey);
  const publicKey = await importPublicKey(ownerPublicKey);
  const wrappedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawKey);
  const packed = new Uint8Array(iv.length + ciphertext.byteLength);
  packed.set(iv, 0);
  packed.set(new Uint8Array(ciphertext), iv.length);
  return {
    blob: new Blob([packed], { type: "application/octet-stream" }),
    wrappedKey: toBase64(new Uint8Array(wrappedKey)),
    aesKey,
    iv,
  };
}

export async function wrapExistingKey(aesKey, recipientPublicKey) {
  const recipient = await importPublicKey(recipientPublicKey);
  const rawKey = await crypto.subtle.exportKey("raw", aesKey);
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, recipient, rawKey);
  return toBase64(new Uint8Array(wrapped));
}

export async function rewrapFileKey(privateKey, wrappedKey, recipientPublicKey) {
  const rawKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    fromBase64(wrappedKey),
  );
  const aesKey = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"],
  );
  return wrapExistingKey(aesKey, recipientPublicKey);
}

export async function decryptFile(ciphertext, privateKey, wrappedKey, filename) {
  const rawKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    fromBase64(wrappedKey),
  );
  const aesKey = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const packed = new Uint8Array(ciphertext);
  if (packed.length < 29) throw new Error("Encrypted file is incomplete.");
  const iv = packed.slice(0, 12);
  const encrypted = packed.slice(12);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, encrypted);
  const blob = new Blob([plaintext], { type: "application/octet-stream" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename || "download";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

export async function sha256Hex(blob) {
  const digest = await crypto.subtle.digest("SHA-256", await blob.arrayBuffer());
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
