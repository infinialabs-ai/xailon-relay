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
  /** Firebase service-account JSON; `/push` answers 503 without it. */
  FCM_SERVICE_ACCOUNT?: string;
};

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
        // One Durable Object per pairing id serializes that channel's
        // deliveries, as the Rust relay's per-id lock does.
        return env.CHANNEL.get(env.CHANNEL.idFromName(query.id)).fetch(request);
      }
      case '/push':
        return request.method === 'POST' ? forwardPush(request, env) : new Response(null, { status: 405 });
      default:
        return new Response('Not Found', { status: 404 });
    }
  },
} satisfies ExportedHandler<Env>;
