/**
 * Public reference example: Primatio Vault Agent Protocol + Playwright login.
 *
 * Demonstrates end-to-end zero-knowledge credential delivery:
 * 1. Generate local ES256 DPoP keypair (never leaves this process).
 * 2. Start RFC 8628 Device Authorization and print `user_code` for Vault App approval.
 * 3. Poll `/vault/v1/oauth/token` at >= 8s intervals (respecting rate limits).
 * 4. Discover authorized login metadata for `PRIMATIO_TARGET_URL`.
 * 5. Create `credential-request` with ephemeral X25519 HPKE public key + `hpke_bind_jwt`.
 * 6. Print 2-digit `match_code` and wait for biometric approval in Vault App.
 * 7. Consume & decrypt HPKE (`X25519 + AES-256-GCM`) envelope in memory only.
 * 8. Fill and submit the login form in Playwright without ever printing secrets.
 *
 * Usage:
 *   PRIMATIO_CLIENT_ID=cli_your_agent_id \
 *   PRIMATIO_TARGET_URL=https://practicetestautomation.com/practice-test-login/ \
 *   npm start
 */

import { randomBytes } from 'node:crypto';
import {
  createDpopProof,
  createHpkeBindJwt,
  generateDpopKey,
} from './dpop.ts';
import {
  generateEphemeralX25519,
  KEM_X25519,
  openEnvelope,
} from './hpke.ts';

const BASE_URL = (process.env.PRIMATIO_BASE_URL || 'https://api.primat.io').replace(/\/$/, '');
const CLIENT_ID = process.env.PRIMATIO_CLIENT_ID || '';
const TARGET_URL =
  process.env.PRIMATIO_TARGET_URL ||
  'https://practicetestautomation.com/practice-test-login/';
const PURPOSE =
  process.env.PRIMATIO_PURPOSE || 'Automated login verification demo';
const HEADLESS = process.env.HEADLESS !== 'false';

if (!CLIENT_ID) {
  console.error(
    'Missing PRIMATIO_CLIENT_ID. Create a DPoP agent in the Primatio Vault app ("My Agents") and pass PRIMATIO_CLIENT_ID=cli_...',
  );
  process.exit(1);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function callJson(
  url: string,
  init: RequestInit,
): Promise<{ status: number; data: Record<string, any> }> {
  const res = await fetch(url, init);
  const text = await res.text();
  let data: Record<string, any> = {};
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }
  return { status: res.status, data };
}

async function main(): Promise<void> {
  const dpop = await generateDpopKey();

  // 1. Start RFC 8628 Device Grant
  const deviceUrl = `${BASE_URL}/vault/v1/oauth/device`;
  const { proof: deviceProof } = await createDpopProof({
    key: dpop,
    method: 'POST',
    htu: deviceUrl,
  });
  const deviceRes = await callJson(deviceUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', DPoP: deviceProof },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      scope: 'vault.logins.metadata:read vault.credentials.request vault.audit:read',
    }),
  });
  if (deviceRes.status !== 200) {
    throw new Error(
      `Device authorization failed (${deviceRes.status}): ${JSON.stringify(deviceRes.data)}`,
    );
  }

  console.log('\n=== Step 1: Approve Agent in Primatio Vault App ===');
  console.log('user_code:', deviceRes.data.user_code);
  console.log(
    'URL:      ',
    deviceRes.data.verification_uri_complete || deviceRes.data.verification_uri,
  );
  console.log('Waiting for approval...\n');

  // 2. Poll token endpoint (>= 8s interval to stay well within 10 req/min throttle)
  const tokenUrl = `${BASE_URL}/vault/v1/oauth/token`;
  const pollMs = Math.max(8000, Number(deviceRes.data.interval || 5) * 1000);
  let accessToken = '';

  const deviceDeadline =
    Date.now() + Number(deviceRes.data.expires_in || 300) * 1000;
  while (Date.now() < deviceDeadline) {
    await sleep(pollMs);
    const { proof: tokenProof } = await createDpopProof({
      key: dpop,
      method: 'POST',
      htu: tokenUrl,
    });
    const tokRes = await callJson(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', DPoP: tokenProof },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: CLIENT_ID,
        device_code: deviceRes.data.device_code,
      }),
    });
    if (tokRes.status === 200 && tokRes.data.access_token) {
      accessToken = tokRes.data.access_token;
      break;
    }
    if (
      tokRes.data.error !== 'authorization_pending' &&
      tokRes.data.error !== 'slow_down'
    ) {
      throw new Error(
        `Token exchange failed (${tokRes.status}): ${JSON.stringify(tokRes.data)}`,
      );
    }
    process.stdout.write('.');
  }
  if (!accessToken) {
    throw new Error('Device authorization timed out.');
  }
  console.log('\nDevice linked successfully.');

  // 3. Discover authorized login for target URL
  const loginsUrl = `${BASE_URL}/vault/v1/agent-clients/${CLIENT_ID}/logins?site=${encodeURIComponent(TARGET_URL)}`;
  const { proof: loginsProof } = await createDpopProof({
    key: dpop,
    method: 'GET',
    htu: loginsUrl,
    accessToken,
  });
  const loginsRes = await callJson(loginsUrl, {
    method: 'GET',
    headers: { Authorization: `DPoP ${accessToken}`, DPoP: loginsProof },
  });
  const login = loginsRes.data.logins?.[0];
  if (!login) {
    throw new Error(
      `No authorized login found for ${TARGET_URL}. Check My Agents scope & discovery toggle.`,
    );
  }
  console.log(
    `Found authorized login: ${login.title || login.site} (${login.username_hint})`,
  );

  // 4. Create credential request with ephemeral X25519 HPKE key + hpke_bind_jwt
  const hpke = await generateEphemeralX25519();
  const reqUrl = `${BASE_URL}/vault/v1/agent-clients/${CLIENT_ID}/credential-requests`;
  const { proof: reqProof } = await createDpopProof({
    key: dpop,
    method: 'POST',
    htu: reqUrl,
    accessToken,
  });
  const reqRes = await callJson(reqUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `DPoP ${accessToken}`,
      DPoP: reqProof,
    },
    body: JSON.stringify({
      item_ref: login.item_ref,
      site: TARGET_URL,
      nonce: randomBytes(16).toString('base64url'),
      purpose: PURPOSE,
      fields: ['username', 'password'],
      ttl_s: 300,
      fc_ephemeral_pub: { kem: KEM_X25519, key: hpke.publicKeyB64 },
    }),
  });
  if (![200, 201, 202].includes(reqRes.status)) {
    throw new Error(
      `Credential request failed (${reqRes.status}): ${JSON.stringify(reqRes.data)}`,
    );
  }

  const requestId: string = reqRes.data.request_id;
  const matchCode: string = reqRes.data.match_code;

  const bindUrl = `${BASE_URL}/vault/v1/agent-clients/${CLIENT_ID}/credential-requests/${requestId}/hpke-bind`;
  const { proof: bindProof } = await createDpopProof({
    key: dpop,
    method: 'POST',
    htu: bindUrl,
    accessToken,
  });
  const bindJwt = await createHpkeBindJwt({
    key: dpop,
    requestId,
    matchCode,
    fcEphemeralPub: { kem: KEM_X25519, key: hpke.publicKeyB64 },
  });
  const bindRes = await callJson(bindUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `DPoP ${accessToken}`,
      DPoP: bindProof,
    },
    body: JSON.stringify({ hpke_bind_jwt: bindJwt }),
  });
  if (bindRes.status !== 200) {
    throw new Error(
      `HPKE bind failed (${bindRes.status}): ${JSON.stringify(bindRes.data)}`,
    );
  }

  console.log('\n=== Step 2: Approve Push Notification in Primatio Vault App ===');
  console.log('request_id:', requestId);
  console.log('match_code:', matchCode);
  console.log('Waiting for biometric approval...\n');

  // 5. Poll until approved and consume HPKE envelope
  const statusUrl = `${BASE_URL}/vault/v1/agent-clients/${CLIENT_ID}/credential-requests/${requestId}`;
  const reqDeadline = Date.now() + 300_000;
  let approved = false;
  while (Date.now() < reqDeadline) {
    await sleep(3000);
    const { proof: statusProof } = await createDpopProof({
      key: dpop,
      method: 'GET',
      htu: statusUrl,
      accessToken,
    });
    const statusRes = await callJson(statusUrl, {
      method: 'GET',
      headers: { Authorization: `DPoP ${accessToken}`, DPoP: statusProof },
    });
    if (statusRes.data.status === 'approved') {
      approved = true;
      break;
    }
    if (
      ['denied', 'expired', 'revoked', 'cancelled'].includes(
        statusRes.data.status,
      )
    ) {
      throw new Error(
        `Credential request ended with status: ${statusRes.data.status}`,
      );
    }
    process.stdout.write('.');
  }
  if (!approved) {
    throw new Error('Credential request timed out waiting for biometric approval.');
  }

  const consumeUrl = `${BASE_URL}/vault/v1/agent-clients/${CLIENT_ID}/credential-requests/${requestId}/consume`;
  const { proof: consumeProof } = await createDpopProof({
    key: dpop,
    method: 'POST',
    htu: consumeUrl,
    accessToken,
  });
  const consumeRes = await callJson(consumeUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `DPoP ${accessToken}`,
      DPoP: consumeProof,
    },
    body: JSON.stringify({}),
  });
  if (consumeRes.status !== 200 || !consumeRes.data.envelope) {
    throw new Error(
      `Consume failed (${consumeRes.status}): ${JSON.stringify(consumeRes.data)}`,
    );
  }

  const plaintextBytes = await openEnvelope({
    envelope: consumeRes.data.envelope,
    recipientPrivateKeyB64: hpke.privateKeyB64,
  });
  const creds = JSON.parse(new TextDecoder().decode(plaintextBytes)) as {
    username?: string;
    password?: string;
  };
  console.log(
    '\nHPKE envelope decrypted in memory (fields:',
    Object.keys(creds).join(', '),
    ')',
  );

  // 6. Use decrypted credentials in Playwright (never logging secret values)
  let playwrightMod: any;
  try {
    const playwrightPkg = 'playwright';
    playwrightMod = await import(playwrightPkg);
  } catch {
    console.log(
      'Playwright is not installed. Install it to run the browser step:\n  npm install --no-save playwright && npx playwright install chromium',
    );
    return;
  }

  const browser = await playwrightMod.chromium.launch({ headless: HEADLESS });
  try {
    const page = await browser.newPage();
    await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded' });
    await page.fill('input[name="username"], #username', creds.username || '');
    await page.fill('input[name="password"], #password', creds.password || '');
    await page.click('button[type="submit"], #submit');
    await page.waitForLoadState('networkidle');
    const bodyText = await page.textContent('body');
    console.log('Browser final URL:', page.url());
    console.log(
      'Login verified:',
      Boolean(
        page.url().includes('logged-in-successfully') ||
          bodyText?.includes('Logged In Successfully'),
      ),
    );
  } finally {
    creds.username = undefined;
    creds.password = undefined;
    await browser.close();
  }
}

main().catch((err) => {
  console.error('Demo failed:', err instanceof Error ? err.message : err);
  process.exit(1);
});
