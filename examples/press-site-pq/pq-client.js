/*
 * QEDOS Press -- application-layer ML-KEM-768 envelope, browser side.
 *
 * Why this exists: tls_compat_pd's outer TLS channel uses classical ECDHE for clients (e.g.
 * iPad/WebKit) that offer no post-quantum group at all. This wraps the actual content exchange in
 * an independent ML-KEM-768 + AES-256-GCM envelope so its confidentiality does not depend on that
 * outer channel staying unbroken forever ("harvest now, decrypt later"). This does NOT protect
 * against an attacker who can already act as a real-time, active man-in-the-middle on the
 * classical TLS connection today (e.g. by presenting a fraudulent but trusted certificate) --
 * only against passively recorded traffic being decrypted in the future. See
 * docs/QEDOS_PRESS_PQ_WRAP.md.
 *
 * Crypto: ml_kem768 from the vendored, audited noble-post-quantum library (vendor/ml-kem768.bundle.js,
 * pinned version -- see third_party/noble-post-quantum/). HKDF-SHA256 and AES-256-GCM use the
 * browser's own Web Crypto API (crypto.subtle), not re-implemented here.
 *
 * Wire format of the POST /press/pq-fetch request body:
 *   [2 bytes path_len, little-endian][path bytes, UTF-8][1088-byte ML-KEM-768 ciphertext]
 * Wire format of the response body (always HTTP 200; the real status is inside the envelope):
 *   [2 bytes app_status, big-endian][12-byte AES-GCM nonce][ciphertext || 16-byte tag]
 */
import { ml_kem768 } from './vendor/ml-kem768.bundle.js';

const HKDF_INFO = new TextEncoder().encode('qedos-press-pq-v1');

async function deriveAesKey(sharedSecret) {
  const baseKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: HKDF_INFO },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
}

function u16le(n) {
  return new Uint8Array([n & 0xff, (n >> 8) & 0xff]);
}

/**
 * Fetch `path` (e.g. "/press/index.html") through the PQ envelope. Returns { status, body }
 * where `body` is the decrypted Uint8Array, or throws if the AEAD tag does not authenticate (a
 * garbage/tampered server response, or a KEM ciphertext that didn't actually match the server's
 * key -- ML-KEM's decapsulation never fails on its own, by design; this is where that kind of
 * forgery is actually caught, not server-side).
 */
export async function pqFetch(path, { pqKeyUrl = '/press/pqkey.bin', fetchUrl = '/press/pq-fetch' } = {}) {
  const pubKeyResp = await fetch(pqKeyUrl);
  if (!pubKeyResp.ok) {
    throw new Error(`pqFetch: failed to fetch PQ public key: ${pubKeyResp.status}`);
  }
  const pubKey = new Uint8Array(await pubKeyResp.arrayBuffer());

  // Fresh encapsulation every call -- forward secrecy at this layer, independent of the outer TLS
  // session.
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(pubKey);
  const aesKey = await deriveAesKey(sharedSecret);

  const pathBytes = new TextEncoder().encode(path);
  const reqBody = new Uint8Array(2 + pathBytes.length + cipherText.length);
  reqBody.set(u16le(pathBytes.length), 0);
  reqBody.set(pathBytes, 2);
  reqBody.set(cipherText, 2 + pathBytes.length);

  const resp = await fetch(fetchUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: reqBody,
  });
  if (!resp.ok) {
    throw new Error(`pqFetch: /press/pq-fetch returned ${resp.status}`);
  }
  const respBytes = new Uint8Array(await resp.arrayBuffer());
  if (respBytes.length < 14) {
    throw new Error('pqFetch: response too short');
  }
  const appStatus = (respBytes[0] << 8) | respBytes[1];
  const nonce = respBytes.slice(2, 14);
  const ciphertext = respBytes.slice(14);

  // AES-GCM decrypt+verify. This throws (rejects) if the tag doesn't authenticate -- the actual
  // "did this really come from someone who held the right shared secret" check.
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ciphertext);
  return { status: appStatus, body: new Uint8Array(plain) };
}
