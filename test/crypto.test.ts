import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import * as jose from 'jose';
import {
  accessTokenHash,
  createDpopProof,
  createHpkeBindJwt,
  generateDpopKey,
  stripQuery,
} from '../src/dpop.ts';
import {
  generateEphemeralX25519,
  KEM_X25519,
  openEnvelope,
  sealEnvelope,
  serializeCanonicalAad,
} from '../src/hpke.ts';

describe('Primatio Agent Protocol crypto helpers', () => {
  it('generates ES256 DPoP proofs without query string and with ath claim', async () => {
    const key = await generateDpopKey();
    const token = 'access-token-sample';
    const { proof } = await createDpopProof({
      key,
      method: 'get',
      htu: 'https://api.primat.io/vault/v1/agent-clients/cli_1/logins?site=example.com',
      accessToken: token,
    });

    const header = jose.decodeProtectedHeader(proof);
    const payload = jose.decodeJwt(proof);

    assert.equal(header.alg, 'ES256');
    assert.equal(header.typ, 'dpop+jwt');
    assert.equal(payload.htm, 'GET');
    assert.equal(
      payload.htu,
      'https://api.primat.io/vault/v1/agent-clients/cli_1/logins',
    );
    assert.equal(payload.ath, accessTokenHash(token));
    assert.equal(
      stripQuery('https://example.com/a?x=1#frag'),
      'https://example.com/a',
    );
  });

  it('signs vault-hpke-bind+jwt with expected audience and claims', async () => {
    const key = await generateDpopKey();
    const hpke = await generateEphemeralX25519();
    const jwt = await createHpkeBindJwt({
      key,
      requestId: 'crq_123',
      matchCode: '42',
      fcEphemeralPub: { kem: KEM_X25519, key: hpke.publicKeyB64 },
    });

    const header = jose.decodeProtectedHeader(jwt);
    const payload = jose.decodeJwt(jwt);

    assert.equal(header.typ, 'vault-hpke-bind+jwt');
    assert.equal(payload.aud, 'vault.credential-request.hpke');
    assert.equal(payload.request_id, 'crq_123');
    assert.equal(payload.match_code, '42');
  });

  it('seals and opens HPKE X25519 + AES-256-GCM envelopes with canonical AAD', async () => {
    const hpke = await generateEphemeralX25519();
    const aad = {
      request_id: 'crq_test',
      item_ref: 'itm_test',
      origin: 'practicetestautomation.com',
      fields: ['username', 'password'],
      exp: 1900000000,
      version: 1,
      integration_id: 'int_test',
    };
    const secret = JSON.stringify({ username: 'student', password: 'Password123' });

    const envelope = await sealEnvelope({
      recipientPublicKeyB64: hpke.publicKeyB64,
      plaintext: new TextEncoder().encode(secret),
      aad,
    });

    const decryptedBytes = await openEnvelope({
      envelope,
      recipientPrivateKeyB64: hpke.privateKeyB64,
    });

    assert.equal(new TextDecoder().decode(decryptedBytes), secret);
    assert.ok(serializeCanonicalAad(aad).startsWith('{"request_id":'));

    // Tampered AAD must fail authentication
    await assert.rejects(() =>
      openEnvelope({
        envelope: {
          ...envelope,
          aad: { ...aad, origin: 'evil.example' },
        },
        recipientPrivateKeyB64: hpke.privateKeyB64,
      }),
    );
  });
});
