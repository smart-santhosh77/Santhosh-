import assert from "node:assert/strict";
import { test } from "node:test";
import { webcrypto } from "node:crypto";

globalThis.crypto ??= webcrypto;

import { createAccountKeys, encryptFile, rewrapFileKey, unlockPrivateKey } from "./crypto.js";

test("account private keys stay password-encrypted and file keys can be shared", async () => {
  const ownerEnvelope = await createAccountKeys("long demo password");
  const ownerPrivateKey = await unlockPrivateKey(ownerEnvelope, "long demo password");
  await assert.rejects(() => unlockPrivateKey(ownerEnvelope, "incorrect password"));

  const recipientPair = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  );
  const recipientPublic = new Uint8Array(await crypto.subtle.exportKey("spki", recipientPair.publicKey));
  const recipientEncoded = Buffer.from(recipientPublic).toString("base64");
  const plain = new Blob(["browser-encrypted content"]);
  const { blob, wrappedKey } = await encryptFile(plain, ownerEnvelope.public_key);

  const ownerRawKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    ownerPrivateKey,
    Buffer.from(wrappedKey, "base64"),
  );
  const ownerAesKey = await crypto.subtle.importKey(
    "raw",
    ownerRawKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const packed = new Uint8Array(await blob.arrayBuffer());
  const ownerPlaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: packed.slice(0, 12) },
    ownerAesKey,
    packed.slice(12),
  );
  assert.equal(new TextDecoder().decode(ownerPlaintext), "browser-encrypted content");

  const recipientWrapped = await rewrapFileKey(ownerPrivateKey, wrappedKey, recipientEncoded);
  const recipientRaw = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    recipientPair.privateKey,
    Buffer.from(recipientWrapped, "base64"),
  );
  assert.deepEqual(new Uint8Array(recipientRaw), new Uint8Array(ownerRawKey));
});
