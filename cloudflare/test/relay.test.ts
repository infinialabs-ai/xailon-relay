import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { channelId, encodeAuthToken } from '../../client-ts/src/relay-client.ts';
import {
  LOCAL_MAX_PENDING_MESSAGES,
  LOCAL_PUSH_PER_HOUR,
  type Relay,
  createClient,
  rawSocket,
  relayId,
  sleep,
  startRelay,
  waitFor,
} from './helpers.ts';

let relay: Relay;

before(async () => {
  relay = await startRelay();
});

after(async () => {
  await relay?.stop();
});

test('health and connect validation', async () => {
  assert.equal(await (await fetch(`${relay.httpUrl}/health`)).text(), 'OK');
  assert.equal((await fetch(`${relay.httpUrl}/nope`)).status, 404);
  const ws = relay.httpUrl;
  assert.equal((await fetch(`${ws}/ws?endpoint=1&device_id=a`)).status, 400);
  assert.equal((await fetch(`${ws}/ws?id=x&endpoint=3&device_id=a`)).status, 400);
  assert.equal((await fetch(`${ws}/ws?id=&endpoint=1&device_id=a`)).status, 400);
  assert.equal((await fetch(`${ws}/ws?id=x&endpoint=1&device_id=a&ack_head=maybe`)).status, 400);
  assert.equal((await fetch(`${ws}/ws?id=${'x'.repeat(257)}&endpoint=1&device_id=a`)).status, 400);
  assert.equal((await fetch(`${ws}/ws?id=x&endpoint=1&device_id=a`)).status, 426);
});

test('pairs two endpoints and delivers durable messages both ways', async () => {
  const id = relayId('pair');
  const host = createClient(relay, { relayId: id, endpoint: '1', deviceId: 'host' });
  const phone = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone' });
  await host.client.connect();
  await phone.client.connect();
  await host.connected();
  await phone.connected();

  await host.client.send({ hello: 'phone' });
  await phone.client.send({ hello: 'host', nested: [1, 2, 3] });
  await waitFor(() => phone.payloads.length === 1 && host.payloads.length === 1, 'both deliveries');
  assert.deepEqual(phone.payloads, [{ hello: 'phone' }]);
  assert.deepEqual(host.payloads, [{ hello: 'host', nested: [1, 2, 3] }]);
  await waitFor(() => host.store.state.outbox.length === 0, 'stored removes the outbox entry');
  host.client.close();
  phone.client.close();
});

test('replays unacknowledged messages after reconnect, in order and once', async () => {
  const id = relayId('replay');
  const host = createClient(relay, { relayId: id, endpoint: '1', deviceId: 'host' });
  // Register the phone, then take it offline.
  const first = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone' });
  await first.client.connect();
  await first.connected();
  first.client.close();

  await host.client.connect();
  await host.connected();
  for (const n of [1, 2, 3]) await host.client.send({ n });
  await waitFor(() => host.store.state.outbox.length === 0, 'all stored while the phone is offline');

  const phone = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone', store: first.store });
  await phone.client.connect();
  await waitFor(() => phone.payloads.length === 3, 'replay');
  assert.deepEqual(phone.payloads, [{ n: 1 }, { n: 2 }, { n: 3 }]);
  await sleep(300);
  phone.client.close();

  const again = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone', store: first.store });
  await again.client.connect();
  await again.connected();
  await sleep(500);
  assert.deepEqual(again.payloads, [], 'acknowledged messages are not replayed');
  host.client.close();
  again.client.close();
});

test('message_id retries are idempotent and conflicting payloads are rejected', async () => {
  const id = relayId('idempotent');
  const receiver = await rawSocket(relay, { id, endpoint: '2', device_id: 'phone' });
  const sender = await rawSocket(relay, { id, endpoint: '1', device_id: 'host' });

  sender.send({ type: 'message', message_id: 'm-1', payload: { once: true } });
  await waitFor(() => receiver.of('message').length === 1, 'first delivery');
  sender.send({ type: 'message', message_id: 'm-1', payload: { once: true } });
  await waitFor(() => sender.of('stored').length === 2, 'retry stored');
  await waitFor(() => receiver.of('message').length === 2, 'pending retry delivered again');
  const [a, b] = receiver.of('message');
  assert.equal(a.sequence, 1);
  assert.equal(b.sequence, 1, 'a retry keeps its sequence');

  receiver.send({ type: 'ack', sequence: 1 });
  await sleep(300);
  sender.send({ type: 'message', message_id: 'm-1', payload: { once: true } });
  await waitFor(() => sender.of('stored').length === 3, 'retry after ack stored');
  await sleep(300);
  assert.equal(receiver.of('message').length, 2, 'acknowledged retry is not delivered');

  sender.send({ type: 'message', message_id: 'm-1', payload: { once: false } });
  await waitFor(() => sender.of('rejected').length === 1, 'conflict rejected');
  assert.equal(sender.of('rejected')[0].reason, 'message_id was already used with a different payload');

  sender.send({ type: 'message', message_id: '', payload: 1 });
  await waitFor(() => sender.of('rejected').length === 2, 'empty id rejected');
  assert.equal(sender.of('rejected')[1].reason, 'message_id must not be empty');

  sender.socket.send('not json');
  sender.send({ type: 'nope' });
  await waitFor(() => sender.of('error').length === 2, 'invalid frames answered with errors');
  assert.match(String(sender.of('error')[0].message), /^invalid frame: /);

  sender.send({ type: 'message', message_id: 'm-2', payload: 2 });
  await waitFor(() => receiver.of('message').length === 3, 'next message gets the next sequence');
  assert.equal(receiver.of('message')[2].sequence, 2);
  receiver.socket.close();
  sender.socket.close();
});

test('targeted delivery and per-device broadcast cursors', async () => {
  const id = relayId('targeted');
  const host = createClient(relay, { relayId: id, endpoint: '1', deviceId: 'host' });
  const phoneA = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone-a' });
  const phoneB = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone-b' });
  for (const c of [host, phoneA, phoneB]) await c.client.connect();
  for (const c of [host, phoneA, phoneB]) await c.connected();

  await host.client.send({ only: 'a' }, 'phone-a');
  await host.client.send({ all: true });
  await waitFor(() => phoneA.payloads.length === 2 && phoneB.payloads.length === 1, 'targeted + broadcast');
  assert.deepEqual(phoneA.payloads, [{ only: 'a' }, { all: true }]);
  assert.deepEqual(phoneB.payloads, [{ all: true }]);

  // B goes offline; a broadcast acknowledged by A stays pending for B.
  phoneB.client.close();
  await host.client.send({ later: true });
  await waitFor(() => phoneA.payloads.length === 3, 'A receives');
  await sleep(300);
  const rejoined = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone-b', store: phoneB.store });
  await rejoined.client.connect();
  await waitFor(() => rejoined.payloads.length === 1, 'B replays the broadcast A already acked');
  assert.deepEqual(rejoined.payloads, [{ later: true }]);
  for (const c of [host, phoneA, rejoined]) c.client.close();
});

test('ephemeral text reaches live devices or reports undeliverable', async () => {
  const id = relayId('ephemeral');
  const host = createClient(relay, { relayId: id, endpoint: '1', deviceId: 'host' });
  await host.client.connect();
  await host.connected();
  const lost = host.client.sendEphemeral({ nobody: 'home' });
  await waitFor(() => host.undeliverable.includes(lost), 'undeliverable');

  const phone = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone' });
  await phone.client.connect();
  await phone.connected();
  host.client.sendEphemeral({ live: true });
  await waitFor(() => phone.payloads.length === 1, 'ephemeral delivered');
  assert.deepEqual(phone.payloads, [{ live: true }]);
  const targeted = host.client.sendEphemeral({ to: 'tablet' }, 'tablet');
  await waitFor(() => host.undeliverable.includes(targeted), 'targeted at an absent device');

  // Ephemeral messages are never stored or replayed.
  phone.client.close();
  const back = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone', store: phone.store });
  await back.client.connect();
  await back.connected();
  await sleep(300);
  assert.deepEqual(back.payloads, []);
  host.client.close();
  back.client.close();
});

test('binary frames are forwarded unchanged', async () => {
  const id = relayId('binary');
  const host = createClient(relay, { relayId: id, endpoint: '1', deviceId: 'host' });
  const phone = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone' });
  await host.client.connect();
  await phone.client.connect();
  await host.connected();
  await phone.connected();

  const body = new Uint8Array(256 * 1024).map((_, i) => i % 251);
  const messageId = host.client.sendBinary(body, undefined, 'bin-1');
  await waitFor(() => phone.binaries.length === 1, 'binary delivered');
  assert.equal(phone.binaries[0].messageId, messageId);
  assert.deepEqual(phone.binaries[0].data, body);

  phone.client.close();
  await sleep(200);
  const lost = host.client.sendBinary(new Uint8Array([1, 2, 3]));
  await waitFor(() => host.undeliverable.includes(lost), 'binary undeliverable');

  const raw = await rawSocket(relay, { id, endpoint: '1', device_id: 'raw' });
  raw.socket.send(new Uint8Array([0]));
  await waitFor(() => raw.of('error').length === 1, 'truncated binary rejected');
  assert.match(String(raw.of('error')[0].message), /^invalid frame: binary frame/);
  raw.socket.close();
  host.client.close();
});

test('a new connection preempts the same device', async () => {
  const id = relayId('preempt');
  const first = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone' });
  await first.client.connect();
  await first.connected();
  const second = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone' });
  await second.client.connect();
  await second.connected();
  await waitFor(() => first.states.at(-1) === 'preempted', 'first preempted');

  const host = createClient(relay, { relayId: id, endpoint: '1', deviceId: 'host' });
  await host.client.connect();
  await host.connected();
  await host.client.send({ to: 'newest' });
  await waitFor(() => second.payloads.length === 1, 'newest connection receives');
  assert.equal(first.payloads.length, 0);
  host.client.close();
  second.client.close();
});

test('ack_head skips the backlog and keeps live delivery', async () => {
  const id = relayId('ackhead');
  const host = createClient(relay, { relayId: id, endpoint: '1', deviceId: 'host' });
  await host.client.connect();
  await host.connected();
  await host.client.send({ stale: 1 });
  await host.client.send({ stale: 2 });
  await waitFor(() => host.store.state.outbox.length === 0, 'backlog stored');

  const phone = await rawSocket(relay, { id, endpoint: '2', device_id: 'phone', ack_head: 'true' });
  await sleep(300);
  assert.equal(phone.of('message').length, 0, 'backlog skipped');
  await host.client.send({ fresh: true });
  await waitFor(() => phone.of('message').length === 1, 'live message');
  assert.deepEqual(phone.of('message')[0].payload, { fresh: true });
  assert.equal(phone.of('message')[0].sequence, 3);
  phone.socket.close();
  host.client.close();
});

test('payloads larger than one storage row survive replay', async () => {
  const id = relayId('large');
  const sender = await rawSocket(relay, { id, endpoint: '1', device_id: 'host' });
  const big = { text: 'é'.repeat(1_500_000) }; // ~3 MB of UTF-8
  sender.send({ type: 'message', message_id: 'big', payload: big });
  await waitFor(() => sender.of('stored').length === 1, 'big payload stored', 30_000);
  const receiver = await rawSocket(relay, { id, endpoint: '2', device_id: 'phone' });
  await waitFor(() => receiver.of('message').length === 1, 'big payload replayed', 30_000);
  assert.deepEqual(receiver.of('message')[0].payload, big);
  sender.socket.close();
  receiver.socket.close();
});

test('messages over 10 MiB close the connection', async () => {
  const sender = await rawSocket(relay, { id: relayId('toobig'), endpoint: '1', device_id: 'host' });
  sender.send({ type: 'message', message_id: 'huge', payload: 'x'.repeat(10 * 1024 * 1024 + 1) });
  await waitFor(() => sender.closed() !== undefined, 'connection closed', 30_000);
  assert.equal(sender.of('stored').length, 0);
});

test('queue_full rejects messages beyond the pending limit', async (t) => {
  if (relay.live) return t.skip('limit is the production default');
  const id = relayId('queue');
  const sender = await rawSocket(relay, { id, endpoint: '1', device_id: 'host' });
  for (let n = 0; n <= LOCAL_MAX_PENDING_MESSAGES; n++) {
    sender.send({ type: 'message', message_id: `q-${n}`, payload: n });
  }
  await waitFor(() => sender.of('stored').length + sender.of('rejected').length === LOCAL_MAX_PENDING_MESSAGES + 1, 'all answered');
  assert.equal(sender.of('stored').length, LOCAL_MAX_PENDING_MESSAGES);
  assert.equal(sender.of('rejected')[0].reason, 'queue_full: pending message count limit reached');
  // A retry of a stored id is still accepted while the queue is full.
  sender.send({ type: 'message', message_id: 'q-0', payload: 0 });
  await waitFor(() => sender.of('stored').length === LOCAL_MAX_PENDING_MESSAGES + 1, 'duplicate accepted');
  sender.socket.close();
});

test('push validates its body, then answers 503 until FCM is configured', async (t) => {
  const post = (body: string) => fetch(`${relay.httpUrl}/push`, { method: 'POST', body });
  assert.equal((await post('{}')).status, 400);
  assert.equal((await post('not json')).status, 400);
  const token = crypto.getRandomValues(new Uint8Array(32));
  const notifications = [{ tokens: ['fcm-token'], data: { agent: 'a', sessionId: 's' } }];
  const response = await post(JSON.stringify({ notifications, id: await channelId(token), auth: encodeAuthToken(token) }));
  if (relay.live && response.status !== 503) return t.skip('push is configured on this relay');
  assert.equal(response.status, 503);
  assert.match((await response.json()).error, /FCM_SERVICE_ACCOUNT/);
  assert.equal((await fetch(`${relay.httpUrl}/push`)).status, 405);
});

const randomToken = () => crypto.getRandomValues(new Uint8Array(32));

/** Opens a raw socket that sends `token` as its first frame. */
const authedSocket = async (id: string, endpoint: '1' | '2', deviceId: string, token?: Uint8Array) => {
  const url = new URL(relay.wsUrl);
  url.search = new URLSearchParams({ id, endpoint, device_id: deviceId, ...(token ? { auth: '1' } : {}) }).toString();
  const socket = new WebSocket(url);
  const frames: Record<string, unknown>[] = [];
  let closed = false;
  socket.addEventListener('open', () => {
    if (token) socket.send(JSON.stringify({ type: 'auth', token: encodeAuthToken(token) }));
  });
  socket.addEventListener('message', (event) => frames.push(JSON.parse(event.data as string)));
  socket.addEventListener('close', () => {
    closed = true;
  });
  await waitFor(() => frames.length > 0 || closed, 'first frame');
  return { socket, frames, closed: () => closed };
};

test('self-certifying channels admit only the token holder', async () => {
  const token = randomToken();
  const id = await channelId(token);
  const host = createClient(relay, { relayId: id, endpoint: '1', deviceId: 'host', authToken: token });
  const phone = createClient(relay, { relayId: id, endpoint: '2', deviceId: 'phone', authToken: token });
  await host.client.connect();
  await phone.client.connect();
  await host.connected();
  await phone.connected();
  await host.client.send({ secret: 'ok' });
  await waitFor(() => phone.payloads.length === 1, 'authenticated delivery');

  // Knowing the id alone cannot preempt the host or purge its backlog.
  const bare = await authedSocket(id, '1', 'host');
  assert.match(String(bare.frames[0]?.message), /^relay_auth_required/);
  await waitFor(() => bare.closed(), 'refused socket closes');
  const wrong = await authedSocket(id, '1', 'host', randomToken());
  assert.match(String(wrong.frames[0]?.message), /^relay_auth_failed/);
  await waitFor(() => wrong.closed(), 'refused socket closes');
  await sleep(300);
  assert.equal(host.states.at(-1), 'connected', 'the host was not preempted');
  await phone.client.send({ still: 'connected' });
  await waitFor(() => host.payloads.length === 1, 'host still receives');
  host.client.close();
  phone.client.close();
});

test('the first authenticated connection claims a legacy id', async () => {
  const id = relayId('claim');
  const legacy = await authedSocket(id, '2', 'old');
  assert.equal(legacy.frames[0]?.type, 'ready', 'unclaimed ids stay open');
  legacy.socket.close();

  const token = randomToken();
  const owner = await authedSocket(id, '1', 'host', token);
  assert.equal(owner.frames[0]?.type, 'ready');
  const bare = await authedSocket(id, '2', 'phone');
  assert.match(String(bare.frames[0]?.message), /^relay_auth_required/);
  const wrong = await authedSocket(id, '2', 'phone', randomToken());
  assert.match(String(wrong.frames[0]?.message), /^relay_auth_failed/);
  const phone = await authedSocket(id, '2', 'phone', token);
  assert.equal(phone.frames[0]?.type, 'ready');
  owner.socket.close();
  phone.socket.close();
});

test('push requires the channel token and has a per-channel budget', async () => {
  const push = (body: unknown) =>
    fetch(`${relay.httpUrl}/push`, { method: 'POST', body: JSON.stringify(body) });
  const notifications = [{ tokens: ['fcm-token'], data: { agent: 'a', sessionId: 's' } }];
  const token = randomToken();
  const id = await channelId(token);

  assert.equal((await push({ notifications })).status, 401, 'no channel auth');
  assert.equal((await push({ notifications, id, auth: encodeAuthToken(randomToken()) })).status, 401, 'wrong token');
  const unclaimed = relayId('push');
  assert.equal(
    (await push({ notifications, id: unclaimed, auth: encodeAuthToken(token) })).status,
    401,
    'an unclaimed legacy channel cannot push',
  );
  // Past the gate the local relay has no FCM credentials, so 503 means "authorized".
  for (let n = 0; n < LOCAL_PUSH_PER_HOUR; n++) {
    assert.equal((await push({ notifications, id, auth: encodeAuthToken(token) })).status, 503);
  }
  assert.equal((await push({ notifications, id, auth: encodeAuthToken(token) })).status, 429, 'budget');
  const tooMany = [{ tokens: Array.from({ length: 11 }, (_, n) => `t${n}`), data: { agent: 'a', sessionId: 's' } }];
  assert.equal((await push({ notifications: tooMany, id, auth: encodeAuthToken(token) })).status, 400);
});
