/**
 * HPKE Base mode (DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM) helpers
 * and canonical AAD serialization for Primatio Vault credential envelopes.
 */

import { Aes256Gcm, CipherSuite, HkdfSha256 } from '@hpke/core';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';

export const KEM_X25519 = 'X25519';
export const ALG_X25519 = 'HPKE-Base/X25519/HKDF-SHA256/AES-256-GCM';

const X25519_KEY_BYTES = 32;
const HPKE_INFO = new Uint8Array(0).buffer;

export type EnvelopeAad = {
  request_id: string;
  item_ref: string;
  origin: string;
  fields: string[];
  exp: number;
  version: number;
  integration_id: string;
};

export type HpkeEnvelope = {
  alg: string;
  kem: string;
  enc: string;
  ct: string;
  aad: EnvelopeAad;
};

export type EphemeralX25519 = {
  kem: string;
  publicKeyB64: string;
  privateKeyB64: string;
};

function createSuite(): CipherSuite {
  return new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function toBase64(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return Buffer.from(view).toString('base64');
}

function fromBase64(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

/**
 * Serializes envelope AAD in the exact canonical key order required by the Primatio Vault protocol.
 */
export function serializeCanonicalAad(aad: EnvelopeAad): string {
  return JSON.stringify({
    request_id: aad.request_id,
    item_ref: aad.item_ref,
    origin: aad.origin,
    fields: aad.fields,
    exp: aad.exp,
    version: aad.version,
    integration_id: aad.integration_id,
  });
}

/**
 * Encodes canonical AAD JSON as UTF-8 bytes.
 */
export function canonicalAadBytes(aad: EnvelopeAad): Uint8Array {
  return new TextEncoder().encode(serializeCanonicalAad(aad));
}

/**
 * Generates an ephemeral X25519 keypair for a single credential request.
 */
export async function generateEphemeralX25519(): Promise<EphemeralX25519> {
  const cs = createSuite();
  const keyPair = await cs.kem.generateKeyPair();
  const publicRaw = await cs.kem.serializePublicKey(keyPair.publicKey);
  const privateRaw = await cs.kem.serializePrivateKey(keyPair.privateKey);
  return {
    kem: KEM_X25519,
    publicKeyB64: toBase64(publicRaw),
    privateKeyB64: toBase64(privateRaw),
  };
}

/**
 * Seals a plaintext payload with HPKE Base mode for testing or local verification.
 */
export async function sealEnvelope(input: {
  recipientPublicKeyB64: string;
  plaintext: Uint8Array;
  aad: EnvelopeAad;
}): Promise<HpkeEnvelope> {
  const cs = createSuite();
  const recipientPublicKey = await cs.kem.deserializePublicKey(
    toArrayBuffer(fromBase64(input.recipientPublicKeyB64)),
  );
  const sender = await cs.createSenderContext({
    recipientPublicKey,
    info: HPKE_INFO,
  });
  const ct = await sender.seal(
    toArrayBuffer(input.plaintext),
    toArrayBuffer(canonicalAadBytes(input.aad)),
  );
  return {
    alg: ALG_X25519,
    kem: KEM_X25519,
    enc: toBase64(sender.enc),
    ct: toBase64(ct),
    aad: input.aad,
  };
}

/**
 * Decrypts a sealed HPKE credential envelope in memory using the ephemeral recipient private key.
 */
export async function openEnvelope(input: {
  envelope: HpkeEnvelope;
  recipientPrivateKeyB64: string;
}): Promise<Uint8Array> {
  const enc = fromBase64(input.envelope.enc);
  if (enc.byteLength !== X25519_KEY_BYTES) {
    throw new Error(
      `Unexpected HPKE encapsulated key size: ${enc.byteLength} bytes (expected ${X25519_KEY_BYTES} for X25519).`,
    );
  }
  const ct = fromBase64(input.envelope.ct);
  const aad = canonicalAadBytes(input.envelope.aad);
  const cs = createSuite();
  const recipientKey = await cs.kem.importKey(
    'raw',
    toArrayBuffer(fromBase64(input.recipientPrivateKeyB64)),
    false,
  );
  const recipient = await cs.createRecipientContext({
    recipientKey,
    enc: toArrayBuffer(enc),
    info: HPKE_INFO,
  });
  const pt = await recipient.open(toArrayBuffer(ct), toArrayBuffer(aad));
  return new Uint8Array(pt);
}
