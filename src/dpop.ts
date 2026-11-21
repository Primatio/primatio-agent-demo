/**
 * ES256 DPoP (RFC 9449) and HPKE-bind JWT helpers for the Primatio Vault Agent Protocol.
 */

import { createHash, randomBytes } from 'node:crypto';
import * as jose from 'jose';

export type DpopJwk = jose.JWK & {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
  d: string;
};

export type DpopKey = {
  privateKey: CryptoKey;
  publicJwk: Omit<DpopJwk, 'd'>;
  privateJwk: DpopJwk;
  jkt: string;
};

/**
 * Generates an ephemeral ES256 (P-256) keypair and its RFC 7638 JWK thumbprint.
 */
export async function generateDpopKey(): Promise<DpopKey> {
  const { privateKey } = await jose.generateKeyPair('ES256', {
    extractable: true,
  });
  const privateJwk = (await jose.exportJWK(privateKey)) as DpopJwk;
  const publicJwk = publicOnly(privateJwk);
  const jkt = await jose.calculateJwkThumbprint(publicJwk, 'sha256');
  return { privateKey, publicJwk, privateJwk, jkt };
}

/**
 * Strips private key material (`d`) from a JWK so only the public key is embedded in headers.
 */
export function publicOnly(jwk: jose.JWK | DpopJwk): Omit<DpopJwk, 'd'> {
  return {
    kty: 'EC',
    crv: 'P-256',
    x: String(jwk.x),
    y: String(jwk.y),
  };
}

/**
 * Computes the base64url-encoded SHA-256 hash of an access token (`ath` claim).
 */
export function accessTokenHash(accessToken: string): string {
  return createHash('sha256').update(accessToken).digest('base64url');
}

/**
 * Strips query parameters and fragments from a URL for the DPoP `htu` claim.
 */
export function stripQuery(rawUrl: string): string {
  const parsed = new URL(rawUrl);
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

/**
 * Signs a DPoP proof JWT (`typ: dpop+jwt`) for an HTTP request.
 */
export async function createDpopProof(input: {
  key: DpopKey;
  method: string;
  htu: string;
  accessToken?: string;
  jti?: string;
  iat?: number;
}): Promise<{ proof: string; jti: string }> {
  const jti = input.jti ?? randomBytes(16).toString('base64url');
  const claims: Record<string, unknown> = {
    htm: input.method.toUpperCase(),
    htu: stripQuery(input.htu),
  };
  if (input.accessToken) {
    claims.ath = accessTokenHash(input.accessToken);
  }
  const jwt = new jose.SignJWT(claims)
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'dpop+jwt',
      jwk: input.key.publicJwk,
    })
    .setJti(jti);

  if (input.iat !== undefined) {
    jwt.setIssuedAt(input.iat);
  } else {
    jwt.setIssuedAt();
  }
  return { proof: await jwt.sign(input.key.privateKey), jti };
}

/**
 * Signs a `vault-hpke-bind+jwt` binding the ephemeral HPKE public key to the DPoP key,
 * `request_id`, and 2-digit `match_code`.
 */
export async function createHpkeBindJwt(input: {
  key: DpopKey;
  requestId: string;
  matchCode: string;
  fcEphemeralPub: { kem: string; key: string };
  jti?: string;
}): Promise<string> {
  const jti = input.jti ?? randomBytes(12).toString('base64url');
  return new jose.SignJWT({
    request_id: input.requestId,
    match_code: input.matchCode,
    fc_ephemeral_pub: input.fcEphemeralPub,
  })
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'vault-hpke-bind+jwt',
      jwk: input.key.publicJwk,
    })
    .setAudience('vault.credential-request.hpke')
    .setIssuedAt()
    .setExpirationTime('2m')
    .setJti(jti)
    .sign(input.key.privateKey);
}
