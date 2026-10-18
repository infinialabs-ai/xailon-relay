import { decodeToken } from './channel';
import type { Env } from './index';

/**
 * Completion-notification forwarder for xailon-orbitd (`crates/daemon/src/push.rs`).
 *
 * The daemon posts a Gorush-style body. Only the device tokens and the
 * agent/session ids are taken from it; the notification itself is built here
 * from a fixed template, so the endpoint cannot be used to send arbitrary
 * content. Messages go out through FCM HTTP v1 (Android directly, iOS through
 * FCM's APNs bridge).
 *
 * The caller proves it is paired: the body names its relay channel (`id`) and
 * carries the channel auth token (`auth`), checked by that channel's Durable
 * Object, which also enforces a per-channel hourly budget.
 */

const MAX_TOKENS = 10;
const MAX_FIELD_BYTES = 4096;
const BODY_LOC_KEY = 'notification_response_complete';
const TITLE = 'XailonOrbit';

type ServiceAccount = { project_id: string; client_email: string; private_key: string; token_uri?: string };

type Push = { token: string; agent: string; sessionId: string };

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const isField = (value: unknown): value is string =>
  typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).length <= MAX_FIELD_BYTES;

const parsePushes = (body: unknown): Push[] | string => {
  const notifications = (body as { notifications?: unknown })?.notifications;
  if (!Array.isArray(notifications)) return 'notifications must be an array';
  const pushes: Push[] = [];
  for (const notification of notifications) {
    const { tokens, data } = (notification ?? {}) as { tokens?: unknown; data?: Record<string, unknown> };
    if (!Array.isArray(tokens) || !tokens.every(isField)) return 'tokens must be non-empty strings';
    if (!isField(data?.agent) || !isField(data?.sessionId)) return 'data.agent and data.sessionId are required';
    for (const token of tokens) pushes.push({ token, agent: data.agent, sessionId: data.sessionId });
  }
  if (pushes.length === 0) return 'no tokens';
  if (pushes.length > MAX_TOKENS) return `at most ${MAX_TOKENS} tokens per request`;
  return pushes;
};

const fcmMessage = ({ token, agent, sessionId }: Push) => {
  // A newer notification of the same session replaces the older one.
  const tag = `${agent}:${sessionId}`;
  return {
    message: {
      token,
      notification: { title: TITLE },
      android: {
        priority: 'HIGH',
        notification: { channel_id: 'agent_responses', body_loc_key: BODY_LOC_KEY, tag },
      },
      apns: {
        headers: { 'apns-collapse-id': tag },
        payload: { aps: { alert: { title: TITLE, 'loc-key': BODY_LOC_KEY }, sound: 'default' } },
      },
      data: { type: 'response_complete', agent, sessionId },
    },
  };
};

const base64Url = (bytes: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

let cachedToken: { key: string; value: string; expires: number } | undefined;

/** OAuth access token for the service account (JWT bearer grant), cached until shortly before expiry. */
const accessToken = async (account: ServiceAccount) => {
  if (cachedToken?.key === account.client_email && cachedToken.expires > Date.now() + 60_000) return cachedToken.value;
  const tokenUri = account.token_uri ?? 'https://oauth2.googleapis.com/token';
  const issued = Math.floor(Date.now() / 1000);
  const encoder = new TextEncoder();
  const unsigned = `${base64Url(encoder.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })))}.${base64Url(
    encoder.encode(
      JSON.stringify({
        iss: account.client_email,
        scope: 'https://www.googleapis.com/auth/firebase.messaging',
        aud: tokenUri,
        iat: issued,
        exp: issued + 3600,
      }),
    ),
  )}`;
  const der = Uint8Array.from(
    atob(account.private_key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')),
    (char) => char.charCodeAt(0),
  );
  const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, encoder.encode(unsigned));
  const response = await fetch(tokenUri, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: `${unsigned}.${base64Url(signature)}`,
    }),
  });
  if (!response.ok) throw new Error(`token request failed: ${response.status} ${await response.text()}`);
  const { access_token, expires_in } = (await response.json()) as { access_token: string; expires_in: number };
  cachedToken = { key: account.client_email, value: access_token, expires: Date.now() + expires_in * 1000 };
  return access_token;
};

export const forwardPush = async (request: Request, env: Env): Promise<Response> => {
  let body: { id?: unknown; auth?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return json({ error: 'body must be JSON' }, 400);
  }
  const pushes = parsePushes(body);
  if (typeof pushes === 'string') return json({ error: pushes }, 400);

  const { id, auth } = body ?? {};
  if (typeof id === 'string' && id && new TextEncoder().encode(id).length <= 256 && decodeToken(auth)) {
    const gate = await env.CHANNEL.get(env.CHANNEL.idFromName(id)).fetch('https://channel/push-auth', {
      method: 'POST',
      body: JSON.stringify({ id, token: auth }),
    });
    if (!gate.ok) return json({ error: await gate.text() }, gate.status);
  } else if (env.ALLOW_UNAUTHENTICATED_PUSH !== 'true') {
    return json({ error: 'push requires the channel id and auth token' }, 401);
  }
  if (!env.FCM_SERVICE_ACCOUNT) {
    return json({ error: 'Push forwarding is not configured: set the FCM_SERVICE_ACCOUNT secret' }, 503);
  }

  const account = JSON.parse(env.FCM_SERVICE_ACCOUNT) as ServiceAccount;
  const token = await accessToken(account);
  const results = await Promise.all(
    pushes.map(async (push) => {
      const response = await fetch(`https://fcm.googleapis.com/v1/projects/${account.project_id}/messages:send`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify(fcmMessage(push)),
      });
      if (!response.ok) console.warn('FCM send failed', response.status, await response.text());
      return response.ok;
    }),
  );
  const sent = results.filter(Boolean).length;
  return json({ success: sent === pushes.length ? 'ok' : 'partial', counts: sent });
};
