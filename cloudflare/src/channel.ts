import { createHash } from 'node:crypto';
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

export type ConnectQuery = { id: string; endpoint: Endpoint; deviceId: string; ackHead: boolean };

/** Mirrors the Rust relay's `ConnectQuery` deserialization and `validate_connection`. */
export const parseConnectQuery = (params: URLSearchParams): ConnectQuery | string => {
  const id = params.get('id');
  const endpoint = params.get('endpoint');
  const deviceId = params.get('device_id');
  const ackHead = (params.get('ack_head') ?? '').toLowerCase();
  if (id === null) return 'Failed to deserialize query string: missing field `id`';
  if (endpoint === null) return 'Failed to deserialize query string: missing field `endpoint`';
  if (deviceId === null) return 'Failed to deserialize query string: missing field `device_id`';
  if (endpoint !== '1' && endpoint !== '2') return 'Failed to deserialize query string: endpoint must be 1 or 2';
  if (!['', 'true', '1', 'yes', 'false', '0', 'no'].includes(ackHead)) {
    return `Failed to deserialize query string: invalid boolean: ${params.get('ack_head')}`;
  }
  if (!id) return 'id must not be empty';
  if (byteLength(id) > MAX_ID_BYTES) return 'id is too long';
  if (!deviceId) return 'device_id must not be empty';
  if (byteLength(deviceId) > MAX_ID_BYTES) return 'device_id is too long';
  return { id, endpoint, deviceId, ackHead: ['true', '1', 'yes'].includes(ackHead) };
};

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
  | { type: 'ack'; sequence: number };

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
  throw new Error('unknown variant, expected `message` or `ack`');
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

type Attachment = { endpoint: Endpoint; deviceId: string; replaced?: boolean };

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
    `);
  }

  async fetch(request: Request): Promise<Response> {
    const query = parseConnectQuery(new URL(request.url).searchParams);
    if (typeof query === 'string') return new Response(query, { status: 400 });
    const { endpoint, deviceId } = query;

    // Preemption: the newest connection for a device replaces the older one.
    // As in the Rust relay, the old client closes on `connection_replaced`;
    // until then it is ignored and receives nothing.
    for (const previous of this.#live(endpoint, deviceId)) {
      previous.serializeAttachment({ ...(previous.deserializeAttachment() as Attachment), replaced: true });
      send(previous, { type: 'error', message: 'connection_replaced: another connection opened for this device' });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, [endpoint, `${endpoint}:${deviceId}`]);
    server.serializeAttachment({ endpoint, deviceId } satisfies Attachment);

    let pending: Stored[];
    try {
      pending = this.ctx.storage.transactionSync(() => {
        this.#registerDevice(endpoint, deviceId);
        if (query.ackHead) this.#acknowledgeHead(endpoint, deviceId);
        return this.#pendingForDevice(endpoint, deviceId);
      });
    } catch (error) {
      console.error('failed to prepare relay device', error);
      send(server, { type: 'error', message: 'relay_storage_unavailable: device registration failed' });
      server.close(1011, 'relay_storage_unavailable');
      return new Response(null, { status: 101, webSocket: client });
    }

    send(server, { type: 'ready', endpoint });
    for (const message of pending) send(server, messageFrame(message));
    await this.#scheduleCleanup();
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(socket: WebSocket, message: string | ArrayBuffer) {
    const attachment = socket.deserializeAttachment() as Attachment;
    if (attachment.replaced) return;
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
    });
    await this.#scheduleCleanup();
  }

  /** Live, non-replaced sockets of an endpoint, optionally only one device. */
  #live(endpoint: Endpoint, deviceId?: string): WebSocket[] {
    return this.ctx
      .getWebSockets(deviceId === undefined ? endpoint : `${endpoint}:${deviceId}`)
      .filter((socket) => !(socket.deserializeAttachment() as Attachment).replaced);
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
          UNION ALL SELECT MIN(last_seen_at) + ? FROM devices)`,
        this.#limits.pendingRetention,
        this.#limits.receiptRetention,
        this.#limits.deviceRetention,
      )
      .one();
    if (due === null) return;
    const at = Math.max(due * 1000 + 1000, Date.now() + MIN_ALARM_DELAY_MS);
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > at) await this.ctx.storage.setAlarm(at);
  }
}
