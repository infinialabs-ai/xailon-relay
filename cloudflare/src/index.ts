import { Channel, parseConnectQuery } from './channel';
import { forwardPush } from './push';

export { Channel };

export type Env = {
  CHANNEL: DurableObjectNamespace<Channel>;
  MAX_PENDING_MESSAGES?: string;
  MAX_PENDING_BYTES?: string;
  PENDING_RETENTION_SECS?: string;
  RECEIPT_RETENTION_SECS?: string;
  DEVICE_RETENTION_SECS?: string;
  /** "true" refuses connections to unclaimed channels that do not authenticate. */
  REQUIRE_AUTH?: string;
  /** Pushes allowed per channel per hour. */
  PUSH_PER_HOUR?: string;
  /** "true" keeps accepting `/push` without channel auth, for daemons that predate it. */
  ALLOW_UNAUTHENTICATED_PUSH?: string;
  /** Optional Workers Rate Limiting bindings, keyed by client IP. */
  CONNECT_LIMITER?: RateLimit;
  PUSH_LIMITER?: RateLimit;
  /** Firebase service-account JSON; `/push` answers 503 without it. */
  FCM_SERVICE_ACCOUNT?: string;
};

const clientIp = (request: Request) => request.headers.get('CF-Connecting-IP') ?? 'unknown';

/** True when the client IP is over the binding's limit; absent bindings never limit. */
const limited = async (limiter: RateLimit | undefined, request: Request) =>
  limiter ? !(await limiter.limit({ key: clientIp(request) })).success : false;

export default {
  async fetch(request, env): Promise<Response> {
    const url = new URL(request.url);
    switch (url.pathname) {
      case '/health':
        return request.method === 'GET' ? new Response('OK') : new Response(null, { status: 405 });
      case '/ws': {
        const query = parseConnectQuery(url.searchParams);
        if (typeof query === 'string') return new Response(query, { status: 400 });
        if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
          return new Response('Expected a WebSocket upgrade', { status: 426 });
        }
        if (await limited(env.CONNECT_LIMITER, request)) return new Response('too many connections', { status: 429 });
        // One Durable Object per pairing id serializes that channel's
        // deliveries, as the Rust relay's per-id lock does.
        return env.CHANNEL.get(env.CHANNEL.idFromName(query.id)).fetch(request);
      }
      case '/push':
        if (request.method !== 'POST') return new Response(null, { status: 405 });
        if (await limited(env.PUSH_LIMITER, request)) return new Response('too many requests', { status: 429 });
        return forwardPush(request, env);
      default:
        return new Response('Not Found', { status: 404 });
    }
  },
} satisfies ExportedHandler<Env>;
