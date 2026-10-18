import { createHash, timingSafeEqual } from 'node:crypto';
import { DurableObject } from 'cloudflare:workers';
import type { Env } from './index';

/**
 * One relay channel (pairing id): the Durable Object port of the Rust relay's
 * `hub.rs` + `database.rs`, scoped to a single id. SQL calls are synchronous
 * and each handler runs to completion before the next, so the per-id delivery
 * lock of the Rust relay is implicit here.
 */

type Endpoint = '1' | '2';

const MAX_ID_BYTES = 256;
const MAX_MESSAGE_BYTES = 10 * 1024 * 1024;
/** DO SQLite rows are capped at 2 MB; payloads are split into chunks of at most ~1.5 MB of UTF-8. */
const PAYLOAD_CHUNK_CHARS = 500_000;
const MIN_ALARM_DELAY_MS = 60_000;
const CLOSE_MESSAGE_TOO_BIG = 1009;

const opposite = (endpoint: Endpoint): Endpoint => (endpoint === '1' ? '2' : '1');
const byteLength = (text: string) => new TextEncoder().encode(text).length;
const now = () => Math.floor(Date.now() / 1000);

export type ConnectQuery = { id: string; endpoint: Endpoint; deviceId: string; ackHead: boolean; auth: boolean };

const BOOLEANS = ['', 'true', '1', 'yes', 'false', '0', 'no'];
const isTrue = (value: string) => ['true', '1', 'yes'].includes(value);

/** Mirrors the Rust relay's `ConnectQuery` deserialization and `validate_connection`. */
export const parseConnectQuery = (params: URLSearchParams): ConnectQuery | string => {
  const id = params.get('id');
  const endpoint = params.get('endpoint');
  const deviceId = params.get('device_id');
  const ackHead = (params.get('ack_head') ?? '').toLowerCase();
  const auth = (params.get('auth') ?? '').toLowerCase();
  if (id === null) return 'Failed to deserialize query string: missing field `id`';
  if (endpoint === null) return 'Failed to deserialize query string: missing field `endpoint`';
  if (deviceId === null) return 'Failed to deserialize query string: missing field `device_id`';
  if (endpoint !== '1' && endpoint !== '2') return 'Failed to deserialize query string: endpoint must be 1 or 2';
  if (!BOOLEANS.includes(ackHead)) {
    return `Failed to deserialize query string: invalid boolean: ${params.get('ack_head')}`;
  }
  if (!BOOLEANS.includes(auth)) return `Failed to deserialize query string: invalid boolean: ${params.get('auth')}`;
  if (!id) return 'id must not be empty';
  if (byteLength(id) > MAX_ID_BYTES) return 'id is too long';
  if (!deviceId) return 'device_id must not be empty';
  if (byteLength(deviceId) > MAX_ID_BYTES) return 'device_id is too long';
  return { id, endpoint, deviceId, ackHead: isTrue(ackHead), auth: isTrue(auth) };
};

/**
 * Channel auth, as in the Rust relay's `relay::auth`. A self-certifying id
 * (`xrc1_…`) is the SHA-256 of its token; any other id is claimed by its first
 * authenticated connection, and only a verifier of the token is stored.
 */
const CHANNEL_ID_PREFIX = 'xrc1_';

const base64Url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** Decodes a base64url (no padding) 32-byte token, or returns null. */
export const decodeToken = (token: unknown): Uint8Array | null => {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const bytes = Uint8Array.from(atob(token.replace(/-/g, '+').replace(/_/g, '/')), (char) => char.charCodeAt(0));
  return bytes.length === 32 && base64Url(bytes) === token ? bytes : null;
};

export const channelId = (token: Uint8Array) =>
  CHANNEL_ID_PREFIX + base64Url(createHash('sha256').update('xailon-relay/channel/v1\0').update(token).digest());

const verifier = (id: string, token: Uint8Array) =>
  createHash('sha256').update('xailon-relay/verifier/v1\0').update(id).update('\0').update(token).digest('hex');

const constantTimeEqual = (a: string, b: string) => {
  const left = new TextEncoder().encode(a);
  const right = new TextEncoder().encode(b);
  return left.length === right.length && timingSafeEqual(left, right);
};

export type AuthResult = 'ok' | 'required' | 'failed';

const validateMessageId = (messageId: string) => {
  if (!messageId) throw new Error('message_id must not be empty');
  if (byteLength(messageId) > MAX_ID_BYTES) throw new Error('message_id is too long');
};

const validateTargetDeviceId = (deviceId: string) => {
  if (!deviceId) throw new Error('target_device_id must not be empty');
  if (byteLength(deviceId) > MAX_ID_BYTES) throw new Error('target_device_id is too long');
};

type ClientFrame =
  | { type: 'message'; message_id: string; payload: unknown; target_device_id?: string; ephemeral: boolean }
  | { type: 'ack'; sequence: number }
  | { type: 'auth'; token: string };

/** Validates a client frame as strictly as the Rust relay's serde types. */
const parseClientFrame = (text: string): ClientFrame => {
  const frame = JSON.parse(text);
  if (!frame || typeof frame !== 'object' || Array.isArray(frame)) throw new Error('expected a frame object');
  if (frame.type === 'ack') {
    if (!Number.isSafeInteger(frame.sequence) || frame.sequence < 0) {
      throw new Error('sequence must be a non-negative integer');
    }
    return { type: 'ack', sequence: frame.sequence };
  }
  if (frame.type === 'auth') {
    if (typeof frame.token !== 'string') throw new Error('token must be a string');
    return { type: 'auth', token: frame.token };
  }
  if (frame.type === 'message') {
    if (typeof frame.message_id !== 'string') throw new Error('message_id must be a string');
    if (!('payload' in frame)) throw new Error('missing field `payload`');
    const target = frame.target_device_id;
    if (target !== undefined && target !== null && typeof target !== 'string') {
      throw new Error('target_device_id must be a string');
    }
    if (frame.ephemeral !== undefined && typeof frame.ephemeral !== 'boolean') {
      throw new Error('ephemeral must be a boolean');
    }
    return {
      type: 'message',
      message_id: frame.message_id,
      payload: frame.payload,
      target_device_id: target ?? undefined,
      ephemeral: frame.ephemeral ?? false,
    };
  }
  throw new Error('unknown variant, expected `message`, `ack` or `auth`');
};

/** `[u16 big-endian header length][header JSON][body]`, as in `decode_binary_frame`. */
const decodeBinaryHeader = (frame: ArrayBuffer): { message_id: string; target_device_id?: string } => {
  if (frame.byteLength < 2) throw new Error('binary frame is missing its header length');
  const bodyStart = 2 + new DataView(frame).getUint16(0);
  if (frame.byteLength < bodyStart) throw new Error('binary frame header is truncated');
  let header: unknown;
  try {
    header = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(new Uint8Array(frame, 2, bodyStart - 2)));
  } catch (error) {
    throw new Error(`invalid binary header: ${(error as Error).message}`);
  }
  const { message_id, target_device_id } = (header ?? {}) as Record<string, unknown>;
  if (typeof message_id !== 'string') throw new Error('invalid binary header: missing field `message_id`');
  if (target_device_id !== undefined && target_device_id !== null && typeof target_device_id !== 'string') {
    throw new Error('invalid binary header: target_device_id must be a string');
  }
  return { message_id, target_device_id: target_device_id ?? undefined };
};

/** `awaitingAuth` sockets have opened with `auth=1` but not yet sent their token; they get and send nothing. */
type Attachment = {
  endpoint: Endpoint;
  deviceId: string;
  replaced?: boolean;
  awaitingAuth?: { id: string; ackHead: boolean };
};

type Stored = { messageId: string; sequence: number; payloadText: string; targetDeviceId: string | null };

const messageFrame = ({ messageId, sequence, payloadText }: Stored) =>
  // The payload is spliced in as stored so large messages are not re-parsed.
  `{"type":"message","message_id":${JSON.stringify(messageId)},"sequence":${sequence},"payload":${payloadText}}`;

const send = (socket: WebSocket, frame: Record<string, unknown> | string) => {
  try {
    socket.send(typeof frame === 'string' ? frame : JSON.stringify(frame));
    return true;
  } catch {
    return false;
  }
};

export class Channel extends DurableObject<Env> {
  #sql: SqlStorage;
  #limits: {
    maxPendingMessages: number;
    maxPendingBytes: number;
    pendingRetention: number;
    receiptRetention: number;
    deviceRetention: number;
  };

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.#sql = ctx.storage.sql;
    const limit = (value: string | undefined, fallback: number) => {
      const parsed = Number(value);
      return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
    };
    this.#limits = {
      maxPendingMessages: limit(env.MAX_PENDING_MESSAGES, 100_000),
      maxPendingBytes: limit(env.MAX_PENDING_BYTES, 1024 * 1024 * 1024),
      pendingRetention: limit(env.PENDING_RETENTION_SECS, 60 * 60),
      receiptRetention: limit(env.RECEIPT_RETENTION_SECS, 60 * 60),
      deviceRetention: limit(env.DEVICE_RETENTION_SECS, 7 * 24 * 60 * 60),
    };
    this.#sql.exec(`
      CREATE TABLE IF NOT EXISTS counters (
        destination TEXT PRIMARY KEY,
        next_sequence INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS receipts (
        source TEXT NOT NULL,
        message_id TEXT NOT NULL,
        destination TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        payload_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (source, message_id)
      );
      CREATE INDEX IF NOT EXISTS receipts_by_sequence ON receipts (destination, sequence);
      CREATE INDEX IF NOT EXISTS receipts_by_created ON receipts (created_at);
      CREATE TABLE IF NOT EXISTS pending (
        destination TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        message_id TEXT NOT NULL,
        payload_bytes INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        target_device_id TEXT,
        PRIMARY KEY (destination, sequence)
      );
      CREATE INDEX IF NOT EXISTS pending_by_created ON pending (created_at);
      CREATE TABLE IF NOT EXISTS pending_chunks (
        destination TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        idx INTEGER NOT NULL,
        data TEXT NOT NULL,
        PRIMARY KEY (destination, sequence, idx)
      );
      CREATE TABLE IF NOT EXISTS devices (
        endpoint TEXT NOT NULL,
        device_id TEXT NOT NULL,
        last_acked_sequence INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        PRIMARY KEY (endpoint, device_id)
      );
      CREATE TABLE IF NOT EXISTS channel_auth (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        verifier TEXT NOT NULL,
        last_seen_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS push_budget (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        hour INTEGER NOT NULL,
        count INTEGER NOT NULL
      );
    `);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/push-auth') return this.#pushAuth(request);
    const query = parseConnectQuery(url.searchParams);
    if (typeof query === 'string') return new Response(query, { status: 400 });
    const { endpoint, deviceId } = query;

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const result = query.auth ? 'ok' : this.#authenticate(query.id, null);
    if (result !== 'ok') {
      // Refused before hibernation: a plain accepted socket delivers the
      // error and the close once the handshake completes.
      server.accept();
      server.serializeAttachment({ endpoint, deviceId } satisfies Attachment);
      this.#refuse(server, result);
      return new Response(null, { status: 101, webSocket: client });
    }
    this.ctx.acceptWebSocket(server, [endpoint, `${endpoint}:${deviceId}`]);
    // Admitted only once authenticated: until then the socket gets nothing
    // and changes nothing about the channel.
    server.serializeAttachment({
      endpoint,
      deviceId,
      awaitingAuth: { id: query.id, ackHead: query.ackHead },
    } satisfies Attachment);
    if (!query.auth) await this.#admit(server, endpoint, deviceId, query.ackHead);
    return new Response(null, { status: 101, webSocket: client });
  }

  /** Registers an authenticated (or legacy) connection: preemption, cursor, backlog, `ready`. */
  async #admit(server: WebSocket, endpoint: Endpoint, deviceId: string, ackHead: boolean) {
    // Preemption: the newest connection for a device replaces the older one.
    // As in the Rust relay, the old client closes on `connection_replaced`;
    // until then it is ignored and receives nothing.
    for (const previous of this.#live(endpoint, deviceId)) {
      previous.serializeAttachment({ ...(previous.deserializeAttachment() as Attachment), replaced: true });
      send(previous, { type: 'error', message: 'connection_replaced: another connection opened for this device' });
    }
    server.serializeAttachment({ endpoint, deviceId } satisfies Attachment);

    let pending: Stored[];
    try {
      pending = this.ctx.storage.transactionSync(() => {
        this.#registerDevice(endpoint, deviceId);
        if (ackHead) this.#acknowledgeHead(endpoint, deviceId);
        return this.#pendingForDevice(endpoint, deviceId);
      });
    } catch (error) {
      console.error('failed to prepare relay device', error);
      send(server, { type: 'error', message: 'relay_storage_unavailable: device registration failed' });
      server.close(1011, 'relay_storage_unavailable');
      return;
    }

    send(server, { type: 'ready', endpoint });
    for (const message of pending) send(server, messageFrame(message));
    await this.#scheduleCleanup();
  }

  #refuse(socket: WebSocket, result: Exclude<AuthResult, 'ok'>) {
    const message =
      result === 'required'
        ? 'relay_auth_required: this channel requires an auth token'
        : 'relay_auth_failed: auth token does not match this channel';
    socket.serializeAttachment({ ...(socket.deserializeAttachment() as Attachment), replaced: true });
    send(socket, { type: 'error', message });
    try {
      socket.close(1008, result === 'required' ? 'relay_auth_required' : 'relay_auth_failed');
    } catch {}
  }

  /** Checks a token against this channel, claiming an unclaimed legacy id. */
  #authenticate(id: string, token: Uint8Array | null): AuthResult {
    if (id.startsWith(CHANNEL_ID_PREFIX)) {
      if (!token) return 'required';
      return constantTimeEqual(channelId(token), id) ? 'ok' : 'failed';
    }
    const [claim] = this.#sql.exec<{ verifier: string }>('SELECT verifier FROM channel_auth WHERE id = 1').toArray();
    if (claim) {
      if (!token) return 'required';
      if (!constantTimeEqual(verifier(id, token), claim.verifier)) return 'failed';
      this.#sql.exec('UPDATE channel_auth SET last_seen_at = ? WHERE id = 1', now());
      return 'ok';
    }
    if (token) {
      this.#sql.exec(
        'INSERT INTO channel_auth (id, verifier, last_seen_at) VALUES (1, ?, ?)',
        verifier(id, token),
        now(),
      );
      return 'ok';
    }
    return this.env.REQUIRE_AUTH === 'true' ? 'required' : 'ok';
  }

  /**
   * `/push` gate: the caller must hold this channel's token (an unclaimed
   * legacy channel cannot push), within a per-channel hourly budget.
   */
  async #pushAuth(request: Request): Promise<Response> {
    const { id, token } = (await request.json()) as { id: string; token: string };
    const decoded = decodeToken(token);
    const unclaimed =
      !id.startsWith(CHANNEL_ID_PREFIX) && this.#sql.exec('SELECT 1 FROM channel_auth WHERE id = 1').toArray().length === 0;
    if (!decoded || unclaimed || this.#authenticate(id, decoded) !== 'ok') {
      return new Response('push requires the channel auth token', { status: 401 });
    }
    const budget = Number(this.env.PUSH_PER_HOUR ?? '120');
    const hour = Math.floor(now() / 3600);
    const { count } = this.#sql
      .exec<{ count: number }>(
        `INSERT INTO push_budget (id, hour, count) VALUES (1, ?, 1)
         ON CONFLICT (id) DO UPDATE SET
           count = CASE WHEN push_budget.hour = excluded.hour THEN push_budget.count + 1 ELSE 1 END,
           hour = excluded.hour
         RETURNING count`,
        hour,
      )
      .one();
    if (Number.isFinite(budget) && budget > 0 && count > budget) {
      return new Response('push budget exceeded for this channel', { status: 429 });
    }
    return new Response('OK');
  }

  async webSocketMessage(socket: WebSocket, message: string | ArrayBuffer) {
    const attachment = socket.deserializeAttachment() as Attachment;
    if (attachment.replaced) return;
    if (attachment.awaitingAuth) {
      let token: Uint8Array | null = null;
      if (typeof message === 'string' && byteLength(message) <= 1024) {
        try {
          const frame = parseClientFrame(message);
          if (frame.type === 'auth') token = decodeToken(frame.token);
        } catch {}
      }
      const result = token ? this.#authenticate(attachment.awaitingAuth.id, token) : 'failed';
      if (result !== 'ok') {
        this.#refuse(socket, result);
        return;
      }
      await this.#admit(socket, attachment.endpoint, attachment.deviceId, attachment.awaitingAuth.ackHead);
      return;
    }
    const size = typeof message === 'string' ? byteLength(message) : message.byteLength;
    if (size > MAX_MESSAGE_BYTES) {
      socket.close(CLOSE_MESSAGE_TOO_BIG, 'Message too big');
      return;
    }

    if (typeof message !== 'string') {
      let header: ReturnType<typeof decodeBinaryHeader>;
      try {
        header = decodeBinaryHeader(message);
      } catch (error) {
        send(socket, { type: 'error', message: `invalid frame: ${(error as Error).message}` });
        return;
      }
      // Forwarded unchanged: receivers parse the same header.
      this.#forwardEphemeral(socket, attachment, header.message_id, header.target_device_id, message);
      return;
    }

    let frame: ClientFrame;
    try {
      frame = parseClientFrame(message);
    } catch (error) {
      send(socket, { type: 'error', message: `invalid frame: ${(error as Error).message}` });
      return;
    }

    if (frame.type === 'auth') {
      send(socket, { type: 'error', message: 'invalid frame: auth is only valid as the first frame' });
      return;
    }

    if (frame.type === 'ack') {
      try {
        this.ctx.storage.transactionSync(() =>
          this.#acknowledge(attachment.endpoint, attachment.deviceId, frame.sequence),
        );
      } catch (error) {
        send(socket, { type: 'error', message: (error as Error).message });
      }
      return;
    }

    if (frame.ephemeral) {
      const text = JSON.stringify({ type: 'ephemeral', message_id: frame.message_id, payload: frame.payload });
      this.#forwardEphemeral(socket, attachment, frame.message_id, frame.target_device_id, text);
      return;
    }

    try {
      const pending = this.ctx.storage.transactionSync(() =>
        this.#store(attachment.endpoint, frame.message_id, frame.payload, frame.target_device_id),
      );
      send(socket, { type: 'stored', message_id: frame.message_id });
      if (pending) {
        const text = messageFrame(pending);
        for (const peer of this.#live(opposite(attachment.endpoint), frame.target_device_id)) send(peer, text);
      }
    } catch (error) {
      send(socket, { type: 'rejected', message_id: frame.message_id, reason: (error as Error).message });
      return;
    }
    await this.#scheduleCleanup();
  }

  async webSocketClose(socket: WebSocket, code: number, reason: string) {
    try {
      socket.close(code === 1005 ? 1000 : code, reason);
    } catch {}
  }

  async webSocketError(socket: WebSocket) {
    try {
      socket.close(1011, 'WebSocket error');
    } catch {}
  }

  async alarm() {
    const time = now();
    const pendingCutoff = time - this.#limits.pendingRetention;
    this.ctx.storage.transactionSync(() => {
      // Receipts of expired deliveries go too, so a retry becomes a fresh delivery.
      this.#sql.exec(
        `DELETE FROM receipts WHERE EXISTS (
          SELECT 1 FROM pending p WHERE p.destination = receipts.destination
            AND p.sequence = receipts.sequence AND p.created_at < ?)`,
        pendingCutoff,
      );
      this.#sql.exec(
        `DELETE FROM pending_chunks WHERE EXISTS (
          SELECT 1 FROM pending p WHERE p.destination = pending_chunks.destination
            AND p.sequence = pending_chunks.sequence AND p.created_at < ?)`,
        pendingCutoff,
      );
      this.#sql.exec('DELETE FROM pending WHERE created_at < ?', pendingCutoff);
      this.#sql.exec('DELETE FROM receipts WHERE created_at < ?', time - this.#limits.receiptRetention);
      this.#sql.exec('DELETE FROM devices WHERE last_seen_at < ?', time - this.#limits.deviceRetention);
      // A claim lapses with its devices, so abandoned ids do not pin storage.
      this.#sql.exec('DELETE FROM channel_auth WHERE last_seen_at < ?', time - this.#limits.deviceRetention);
    });
    await this.#scheduleCleanup();
  }

  /** Live, admitted sockets of an endpoint, optionally only one device. */
  #live(endpoint: Endpoint, deviceId?: string): WebSocket[] {
    return this.ctx
      .getWebSockets(deviceId === undefined ? endpoint : `${endpoint}:${deviceId}`)
      .filter((socket) => {
        const attachment = socket.deserializeAttachment() as Attachment;
        return !attachment.replaced && !attachment.awaitingAuth;
      });
  }

  /** Forwards to the peer endpoint's live devices without storage; the sender only hears back when none took it. */
  #forwardEphemeral(
    socket: WebSocket,
    { endpoint }: Attachment,
    messageId: string,
    targetDeviceId: string | undefined,
    message: string | ArrayBuffer,
  ) {
    try {
      validateMessageId(messageId);
      if (targetDeviceId !== undefined) validateTargetDeviceId(targetDeviceId);
    } catch (error) {
      send(socket, { type: 'rejected', message_id: messageId, reason: (error as Error).message });
      return;
    }
    let delivered = 0;
    for (const peer of this.#live(opposite(endpoint), targetDeviceId)) {
      try {
        peer.send(message);
        delivered += 1;
      } catch {}
    }
    if (delivered === 0) {
      send(socket, {
        type: 'undeliverable',
        message_id: messageId,
        reason: 'no connected device accepted the message',
      });
    }
  }

  #store(source: Endpoint, messageId: string, payload: unknown, targetDeviceId: string | undefined): Stored | null {
    validateMessageId(messageId);
    if (targetDeviceId !== undefined) validateTargetDeviceId(targetDeviceId);
    const destination = opposite(source);
    const payloadText = JSON.stringify(payload);
    const payloadBytes = byteLength(payloadText);
    const payloadHash = createHash('sha256').update(payloadText).digest('hex');
    const time = now();

    const [receipt] = this.#sql
      .exec<{ destination: string; sequence: number; payload_hash: string }>(
        'SELECT destination, sequence, payload_hash FROM receipts WHERE source = ? AND message_id = ?',
        source,
        messageId,
      )
      .toArray();
    let sequence: number;
    if (receipt) {
      if (receipt.destination !== destination || receipt.payload_hash !== payloadHash) {
        throw new Error('message_id was already used with a different payload');
      }
      sequence = receipt.sequence;
    } else {
      const { count, bytes } = this.#sql
        .exec<{ count: number; bytes: number | null }>(
          'SELECT COUNT(*) AS count, SUM(payload_bytes) AS bytes FROM pending WHERE destination = ?',
          destination,
        )
        .one();
      if (count >= this.#limits.maxPendingMessages) throw new Error('queue_full: pending message count limit reached');
      if (payloadBytes > this.#limits.maxPendingBytes || (bytes ?? 0) > this.#limits.maxPendingBytes - payloadBytes) {
        throw new Error('queue_full: pending payload byte limit reached');
      }
      sequence =
        (this.#sql
          .exec<{ next_sequence: number }>('SELECT next_sequence FROM counters WHERE destination = ?', destination)
          .toArray()[0]?.next_sequence ?? 0) + 1;
      this.#sql.exec(
        `INSERT INTO counters (destination, next_sequence) VALUES (?, ?)
         ON CONFLICT (destination) DO UPDATE SET next_sequence = excluded.next_sequence`,
        destination,
        sequence,
      );
      this.#sql.exec(
        'INSERT INTO receipts (source, message_id, destination, sequence, payload_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        source,
        messageId,
        destination,
        sequence,
        payloadHash,
        time,
      );
      this.#sql.exec(
        'INSERT INTO pending (destination, sequence, message_id, payload_bytes, created_at, target_device_id) VALUES (?, ?, ?, ?, ?, ?)',
        destination,
        sequence,
        messageId,
        payloadBytes,
        time,
        targetDeviceId ?? null,
      );
      for (let idx = 0; idx * PAYLOAD_CHUNK_CHARS < payloadText.length; idx++) {
        this.#sql.exec(
          'INSERT INTO pending_chunks (destination, sequence, idx, data) VALUES (?, ?, ?, ?)',
          destination,
          sequence,
          idx,
          payloadText.slice(idx * PAYLOAD_CHUNK_CHARS, (idx + 1) * PAYLOAD_CHUNK_CHARS),
        );
      }
    }

    // A retry of a still-pending message is delivered again; an acknowledged one is not.
    const [pending] = this.#sql
      .exec<{ target_device_id: string | null }>(
        'SELECT target_device_id FROM pending WHERE destination = ? AND sequence = ?',
        destination,
        sequence,
      )
      .toArray();
    return pending ? { messageId, sequence, payloadText, targetDeviceId: pending.target_device_id } : null;
  }

  #registerDevice(endpoint: Endpoint, deviceId: string) {
    this.#sql.exec(
      `INSERT INTO devices (endpoint, device_id, last_acked_sequence, last_seen_at) VALUES (?, ?, 0, ?)
       ON CONFLICT (endpoint, device_id) DO UPDATE SET last_seen_at = excluded.last_seen_at`,
      endpoint,
      deviceId,
      now(),
    );
  }

  #pendingForDevice(endpoint: Endpoint, deviceId: string): Stored[] {
    const lastAcked =
      this.#sql
        .exec<{ last_acked_sequence: number }>(
          'SELECT last_acked_sequence FROM devices WHERE endpoint = ? AND device_id = ?',
          endpoint,
          deviceId,
        )
        .toArray()[0]?.last_acked_sequence ?? 0;
    const rows = this.#sql
      .exec<{ sequence: number; message_id: string; target_device_id: string | null }>(
        `SELECT sequence, message_id, target_device_id FROM pending
         WHERE destination = ? AND sequence > ? AND (target_device_id IS NULL OR target_device_id = ?)
         ORDER BY sequence`,
        endpoint,
        lastAcked,
        deviceId,
      )
      .toArray();
    return rows.map((row) => ({
      messageId: row.message_id,
      sequence: row.sequence,
      targetDeviceId: row.target_device_id,
      payloadText: this.#sql
        .exec<{ data: string }>(
          'SELECT data FROM pending_chunks WHERE destination = ? AND sequence = ? ORDER BY idx',
          endpoint,
          row.sequence,
        )
        .toArray()
        .map((chunk) => chunk.data)
        .join(''),
    }));
  }

  #acknowledge(endpoint: Endpoint, deviceId: string, sequence: number) {
    this.#sql.exec(
      `INSERT INTO devices (endpoint, device_id, last_acked_sequence, last_seen_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (endpoint, device_id) DO UPDATE SET
         last_acked_sequence = excluded.last_acked_sequence, last_seen_at = excluded.last_seen_at
       WHERE excluded.last_acked_sequence > devices.last_acked_sequence`,
      endpoint,
      deviceId,
      sequence,
      now(),
    );
    this.#purgeAcknowledged(endpoint, deviceId, sequence);
  }

  /** `ack_head`: moves the device's cursor to the latest sequence, dropping its unread backlog. */
  #acknowledgeHead(endpoint: Endpoint, deviceId: string) {
    const head =
      this.#sql
        .exec<{ next_sequence: number }>('SELECT next_sequence FROM counters WHERE destination = ?', endpoint)
        .toArray()[0]?.next_sequence ?? 0;
    this.#sql.exec(
      'UPDATE devices SET last_acked_sequence = ?, last_seen_at = ? WHERE endpoint = ? AND device_id = ?',
      head,
      now(),
      endpoint,
      deviceId,
    );
    this.#purgeAcknowledged(endpoint, deviceId, head);
  }

  /**
   * Broadcasts go once every device seen within the retention window has
   * acknowledged them; messages targeted at this device go at its own cursor.
   */
  #purgeAcknowledged(endpoint: Endpoint, deviceId: string, sequence: number) {
    const { min_acked } = this.#sql
      .exec<{ min_acked: number | null }>(
        'SELECT MIN(last_acked_sequence) AS min_acked FROM devices WHERE endpoint = ? AND last_seen_at >= ?',
        endpoint,
        now() - this.#limits.deviceRetention,
      )
      .one();
    const minAcked = min_acked ?? sequence;
    const condition = `destination = ? AND (
      (target_device_id IS NULL AND sequence <= ?) OR (target_device_id = ? AND sequence <= ?))`;
    this.#sql.exec(
      `DELETE FROM pending_chunks WHERE (destination, sequence) IN (
        SELECT destination, sequence FROM pending WHERE ${condition})`,
      endpoint,
      minAcked,
      deviceId,
      sequence,
    );
    this.#sql.exec(`DELETE FROM pending WHERE ${condition}`, endpoint, minAcked, deviceId, sequence);
  }

  /** Wakes at the next expiry instead of polling, so idle channels cost nothing. */
  async #scheduleCleanup() {
    const { due } = this.#sql
      .exec<{ due: number | null }>(
        `SELECT MIN(due) AS due FROM (
          SELECT MIN(created_at) + ? AS due FROM pending
          UNION ALL SELECT MIN(created_at) + ? FROM receipts
          UNION ALL SELECT MIN(last_seen_at) + ? FROM devices
          UNION ALL SELECT MIN(last_seen_at) + ? FROM channel_auth)`,
        this.#limits.pendingRetention,
        this.#limits.receiptRetention,
        this.#limits.deviceRetention,
        this.#limits.deviceRetention,
      )
      .one();
    if (due === null) return;
    const at = Math.max(due * 1000 + 1000, Date.now() + MIN_ALARM_DELAY_MS);
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > at) await this.ctx.storage.setAlarm(at);
  }
}
