import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import formbody from '@fastify/formbody';
import websocket from '@fastify/websocket';
import Twilio from 'twilio';
import { registerInboundRoutes } from '../inbound-calls.js';
import { registerOutboundRoutes } from '../outbound-calls.js';
import { publicOrigin, requireTwilioSignature } from '../request-security.js';

const origin = 'https://voice.example.invalid';
const callToken = 'synthetic-call-token-for-tests-only-12345';
const authToken = 'synthetic-twilio-token';
Object.assign(process.env, {
  PUBLIC_ORIGIN: origin, OUTBOUND_CALL_TOKEN: callToken,
  TWILIO_AUTH_TOKEN: authToken, TWILIO_ACCOUNT_SID: 'AC' + '0'.repeat(32),
  TWILIO_PHONE_NUMBER: '+15555550100', ELEVENLABS_API_KEY: 'synthetic-key',
  ELEVENLABS_AGENT_ID: 'synthetic-agent',
});

async function application(t, { token = callToken } = {}) {
  const previous = process.env.OUTBOUND_CALL_TOKEN;
  process.env.OUTBOUND_CALL_TOKEN = token;
  const app = Fastify();
  const calls = [];
  await app.register(formbody);
  await app.register(websocket);
  registerInboundRoutes(app);
  registerOutboundRoutes(app, { client: { calls: { create: async options => {
    calls.push(options); return { sid: 'synthetic-call-id' };
  } } } });
  process.env.OUTBOUND_CALL_TOKEN = previous;
  await app.ready();
  t.after(() => app.close());
  return { app, calls };
}

for (const value of [undefined, 'http://example.invalid', 'https://user:pass@example.invalid', 'https://example.invalid/path', 'https://example.invalid?x=y', 'https://example.invalid#fragment']) {
  test(`reject invalid public origin ${value}`, () => {
    // Explicit undefined would otherwise select the environment default.
    assert.throws(() => publicOrigin(value === undefined ? '' : value));
  });
}

test('normalizes a valid HTTPS origin', () => {
  assert.equal(publicOrigin(origin + '/'), origin);
});

for (const authorization of [undefined, 'Bearer wrong', 'Basic wrong']) {
  test(`reject unauthorized dial requests (${authorization}) before creating a call`, async t => {
    const { app, calls } = await application(t);
    const response = await app.inject({ method: 'POST', url: '/outbound-call',
      headers: authorization ? { authorization } : {}, payload: { number: '+15555550123' } });
    assert.equal(response.statusCode, 401);
    assert.equal(calls.length, 0);
  });
}

test('missing call token fails closed', async t => {
  const { app, calls } = await application(t, { token: '' });
  const response = await app.inject({ method: 'POST', url: '/outbound-call', payload: { number: '+15555550123' } });
  assert.equal(response.statusCode, 503);
  assert.equal(calls.length, 0);
});

for (const payload of [{}, { number: 'not-a-phone' }, { number: '+15555550123', prompt: 'x'.repeat(4001) }]) {
  test(`reject invalid dial input ${Object.keys(payload).join(',')}`, async t => {
    const { app, calls } = await application(t);
    const response = await app.inject({ method: 'POST', url: '/outbound-call',
      headers: { authorization: `Bearer ${callToken}` }, payload });
    assert.equal(response.statusCode, 400);
    assert.equal(calls.length, 0);
  });
}

test('authorized dialing uses the configured callback origin, not Host', async t => {
  const { app, calls } = await application(t);
  const response = await app.inject({ method: 'POST', url: '/outbound-call',
    headers: { authorization: `Bearer ${callToken}`, host: 'attacker.example' },
    payload: { number: '+15555550123', prompt: 'Hello & welcome' } });
  assert.equal(response.statusCode, 200);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${origin}/outbound-call-twiml?prompt=Hello%20%26%20welcome`);
});

for (const path of ['/incoming-call-eleven', '/outbound-call-twiml', '/media-stream', '/outbound-media-stream']) {
  test(`reject unsigned Twilio traffic at ${path}`, async t => {
    const { app } = await application(t);
    const response = await app.inject({ method: 'GET', url: path });
    assert.equal(response.statusCode, 403);
  });
}

test('signed TwiML escapes prompt XML and uses the configured stream origin', async t => {
  const { app } = await application(t);
  const path = '/outbound-call-twiml?prompt=' + encodeURIComponent('A "quote" & <tag>');
  const signature = Twilio.getExpectedTwilioSignature(authToken, origin + path, {});
  const response = await app.inject({ method: 'GET', url: path,
    headers: { 'x-twilio-signature': signature, host: 'attacker.example' } });
  assert.equal(response.statusCode, 200);
  assert.match(response.body, /A &quot;quote&quot; &amp; &lt;tag(?:>|&gt;)/);
  assert.doesNotMatch(response.body, /<tag>/);
  assert.match(response.body, /wss:\/\/voice\.example\.invalid\/outbound-media-stream/);
  assert.doesNotMatch(response.body, /attacker\.example/);
});

test('signed POST validates form parameters', async t => {
  const { app } = await application(t);
  const path = '/incoming-call-eleven';
  const body = { CallSid: 'CA-test', From: '+15555550123' };
  const signature = Twilio.getExpectedTwilioSignature(authToken, origin + path, body);
  const response = await app.inject({ method: 'POST', url: path,
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-twilio-signature': signature },
    payload: new URLSearchParams(body).toString() });
  assert.equal(response.statusCode, 200);
  const altered = await app.inject({ method: 'POST', url: path,
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'x-twilio-signature': signature },
    payload: new URLSearchParams({ ...body, From: '+15555550999' }).toString() });
  assert.equal(altered.statusCode, 403);
});

test('reject signatures for another public host or path', async t => {
  const { app } = await application(t);
  const signature = Twilio.getExpectedTwilioSignature(authToken, 'https://other.invalid/incoming-call-eleven', {});
  const response = await app.inject({ url: '/incoming-call-eleven', headers: { 'x-twilio-signature': signature } });
  assert.equal(response.statusCode, 403);
});

for (const scheme of ['https:', 'wss:']) {
  test(`validate the configured media handshake signed with ${scheme}`, async t => {
    const app = Fastify();
    app.get('/stream', { preValidation: requireTwilioSignature(origin, { websocket: true, token: authToken }) }, async () => ({ ok: true }));
    t.after(() => app.close());
    const signature = Twilio.getExpectedTwilioSignature(authToken, origin.replace('https:', scheme) + '/stream', {});
    const response = await app.inject({ url: '/stream', headers: { 'x-twilio-signature': signature } });
    assert.equal(response.statusCode, 200);
  });
}
