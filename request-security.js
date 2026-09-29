import { timingSafeEqual } from 'node:crypto';
import Twilio from 'twilio';

export function publicOrigin(value = process.env.PUBLIC_ORIGIN) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('PUBLIC_ORIGIN must be an HTTPS origin without credentials, path, query, or fragment');
  }
  return url.origin;
}

export function requireCallToken(token = process.env.OUTBOUND_CALL_TOKEN) {
  return async function authorizeCall(request, reply) {
    if (typeof token !== 'string' || token.length < 32) {
      return reply.code(503).send({ error: 'Outbound calling is not configured' });
    }
    const header = request.headers.authorization;
    const supplied = typeof header === 'string' && /^Bearer /i.test(header) ? header.slice(7) : '';
    const expected = Buffer.from(token);
    const actual = Buffer.from(supplied);
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
      return reply.code(401).send({ error: 'Unauthorized' });
    }
  };
}

export function requireTwilioSignature(origin, { websocket = false, token = process.env.TWILIO_AUTH_TOKEN } = {}) {
  return async function authorizeTwilio(request, reply) {
    if (!token) return reply.code(503).send({ error: 'Twilio validation is not configured' });
    const signature = request.headers['x-twilio-signature'];
    if (typeof signature !== 'string' || !signature) return reply.code(403).send({ error: 'Invalid Twilio signature' });
    // Reconstruct the externally configured URL, never an untrusted Host header.
    const url = `${origin}${request.raw.url}`;
    const params = request.method === 'POST' ? (request.body || {}) : {};
    const urls = websocket ? [url, url.replace(/^https:/, 'wss:')] : [url];
    let valid = false;
    try {
      valid = urls.some(candidate => Twilio.validateRequest(token, signature, candidate, params));
    } catch {
      valid = false;
    }
    if (!valid) return reply.code(403).send({ error: 'Invalid Twilio signature' });
  };
}
