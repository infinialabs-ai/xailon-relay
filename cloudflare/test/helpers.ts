import { type ChildProcess, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  type OutboundMessage,
  RelayClient,
  type RelayConnectionState,
  type RelayStore,
} from '../../client-ts/src/relay-client.ts';

/** Small enough for the queue_full test; each test uses its own pairing id. */
export const LOCAL_MAX_PENDING_MESSAGES = 5;

export const waitFor = async (condition: () => boolean, what: string, timeout = 10_000) => {
  const start = Date.now();
  while (!condition()) {
    if (Date.now() - start > timeout) throw new Error(`Timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
};

export const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const freePort = () =>
  new Promise<number>((resolve, reject) => {
    const server = createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });

export type Relay = { wsUrl: string; httpUrl: string; live: boolean; stop: () => Promise<void> };

/** `RELAY_URL=wss://host/ws` runs against a deployed relay; otherwise a local `wrangler dev`. */
export const startRelay = async (): Promise<Relay> => {
  if (process.env.RELAY_URL) {
    const wsUrl = process.env.RELAY_URL;
    const httpUrl = wsUrl.replace(/^ws/, 'http').replace(/\/ws$/, '');
    return { wsUrl, httpUrl, live: true, stop: async () => {} };
  }
  const port = await freePort();
  const persist = mkdtempSync(join(tmpdir(), 'xailon-relay-test-'));
  const child: ChildProcess = spawn(
    'npx',
    [
      'wrangler',
      'dev',
      '--ip',
      '127.0.0.1',
      '--port',
      String(port),
      '--persist-to',
      persist,
      '--var',
      `MAX_PENDING_MESSAGES:${LOCAL_MAX_PENDING_MESSAGES}`,
      '--show-interactive-dev-session=false',
    ],
    { cwd: new URL('..', import.meta.url).pathname, stdio: ['ignore', 'pipe', 'pipe'], env: process.env },
  );
  let output = '';
  child.stdout?.on('data', (chunk) => (output += chunk));
  child.stderr?.on('data', (chunk) => (output += chunk));
  const httpUrl = `http://127.0.0.1:${port}`;
  const start = Date.now();
  for (;;) {
    try {
      if ((await fetch(`${httpUrl}/health`)).ok) break;
    } catch {}
    if (Date.now() - start > 60_000 || child.exitCode !== null) {
      child.kill();
      throw new Error(`wrangler dev did not start:\n${output}`);
    }
    await sleep(250);
  }
  return {
    wsUrl: `ws://127.0.0.1:${port}/ws`,
    httpUrl,
    live: false,
    stop: async () => {
      child.kill('SIGINT');
      await new Promise((resolve) => child.once('exit', resolve));
      rmSync(persist, { recursive: true, force: true });
    },
  };
};

export const memoryStore = (deviceId: string): RelayStore & { state: { outbox: OutboundMessage[]; lastReceived?: number } } => {
  const state: { outbox: OutboundMessage[]; lastReceived?: number } = { outbox: [] };
  return {
    state,
    outbox: () => [...state.outbox],
    enqueue: (message) => {
      state.outbox.push(message);
    },
    removeFromOutbox: (messageId) => {
      state.outbox = state.outbox.filter((message) => message.messageId !== messageId);
    },
    lastReceived: () => state.lastReceived,
    markReceived: (sequence) => {
      state.lastReceived = sequence;
    },
    deviceId: () => deviceId,
  };
};

export type TestClient = {
  client: RelayClient;
  store: ReturnType<typeof memoryStore>;
  payloads: unknown[];
  binaries: { data: Uint8Array; messageId: string }[];
  undeliverable: string[];
  states: RelayConnectionState[];
  connected: () => Promise<void>;
};

export const relayId = (name: string) => `test-${name}-${crypto.randomUUID()}`;

export const createClient = (
  relay: Relay,
  options: { relayId: string; endpoint: '1' | '2'; deviceId: string; store?: ReturnType<typeof memoryStore> },
): TestClient => {
  const store = options.store ?? memoryStore(options.deviceId);
  const result: Omit<TestClient, 'client' | 'connected'> = {
    store,
    payloads: [],
    binaries: [],
    undeliverable: [],
    states: [],
  };
  const client = new RelayClient({
    relayId: options.relayId,
    endpoint: options.endpoint,
    deviceId: options.deviceId,
    relayUrl: relay.wsUrl,
    store,
    onPayload: (payload) => {
      result.payloads.push(payload);
    },
    onBinary: (data, messageId) => {
      result.binaries.push({ data: new Uint8Array(data), messageId });
    },
    onUndeliverable: (messageId) => {
      result.undeliverable.push(messageId);
    },
    onStateChange: (state) => {
      result.states.push(state);
    },
  });
  return {
    ...result,
    client,
    connected: () => waitFor(() => result.states.at(-1) === 'connected', `${options.deviceId} to connect`),
  };
};

/** A bare socket for frame-level assertions. */
export const rawSocket = async (relay: Relay, query: Record<string, string>) => {
  const url = new URL(relay.wsUrl);
  for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
  const socket = new WebSocket(url);
  socket.binaryType = 'arraybuffer';
  const frames: Record<string, unknown>[] = [];
  const binaries: ArrayBuffer[] = [];
  let closed: { code: number; reason: string } | undefined;
  socket.addEventListener('message', (event) => {
    if (typeof event.data === 'string') frames.push(JSON.parse(event.data));
    else binaries.push(event.data as ArrayBuffer);
  });
  socket.addEventListener('close', (event) => {
    closed = { code: event.code, reason: event.reason };
  });
  await waitFor(() => frames.some((frame) => frame.type === 'ready') || closed !== undefined, 'raw socket ready');
  return {
    socket,
    frames,
    binaries,
    closed: () => closed,
    send: (frame: unknown) => socket.send(JSON.stringify(frame)),
    of: (type: string) => frames.filter((frame) => frame.type === type),
  };
};
