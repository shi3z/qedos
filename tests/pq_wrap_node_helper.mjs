// Minimal CLI helper used ONLY by tests/test_press_pqwrap_sel4.py to perform the exact same
// client-side crypto as examples/press-site/pq-client.js (same vendored ml_kem768, same Web
// Crypto HKDF/AES-GCM calls), so the Python test driver can own the raw TLS/HTTP exchange while
// this process does only the crypto -- avoids re-implementing ML-KEM-768 in Python.
//
// Usage:
//   node pq_wrap_node_helper.mjs encap <pubkey_bin_file> <out_capsule_file> <out_sharedsecret_file>
//   node pq_wrap_node_helper.mjs garbage-capsule <out_capsule_file>
//   node pq_wrap_node_helper.mjs decrypt <sharedsecret_file> <nonce_file> <ciphertext_file> <out_plain_file>
import { readFileSync, writeFileSync } from 'node:fs';
import { ml_kem768 } from '../examples/press-site-pq/vendor/ml-kem768.bundle.js';

const HKDF_INFO = new TextEncoder().encode('qedos-press-pq-v1');

async function deriveAesKey(sharedSecret) {
  const baseKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: HKDF_INFO },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt'],
  );
}

async function main() {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === 'encap') {
    const [pubFile, outCapsule, outSecret] = args;
    const pub = new Uint8Array(readFileSync(pubFile));
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(pub);
    writeFileSync(outCapsule, Buffer.from(cipherText));
    writeFileSync(outSecret, Buffer.from(sharedSecret));
  } else if (mode === 'garbage-capsule') {
    const [outCapsule] = args;
    const garbage = new Uint8Array(1088);
    crypto.getRandomValues(garbage);
    writeFileSync(outCapsule, Buffer.from(garbage));
  } else if (mode === 'decrypt') {
    const [secretFile, nonceFile, ctFile, outPlain] = args;
    const sharedSecret = new Uint8Array(readFileSync(secretFile));
    const nonce = new Uint8Array(readFileSync(nonceFile));
    const ciphertext = new Uint8Array(readFileSync(ctFile));
    const key = await deriveAesKey(sharedSecret);
    try {
      const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, ciphertext);
      writeFileSync(outPlain, Buffer.from(plain));
      console.log('OK');
    } catch (e) {
      console.log('AEAD_FAIL');
    }
  } else {
    console.error(`unknown mode: ${mode}`);
    process.exit(2);
  }
}

main();
