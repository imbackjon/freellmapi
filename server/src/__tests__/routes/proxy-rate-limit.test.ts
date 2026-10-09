import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Express } from 'express';
import { createApp } from '../../app.js';
import { initDb } from '../../db/index.js';

async function request(app: Express, headers: Record<string, string> = {}) {
  const server = app.listen(0, '127.0.0.1');
  if (!server.listening) await new Promise<void>(resolve => server.once('listening', () => resolve()));
  const addr = server.address() as any;
  const url = `http://127.0.0.1:${addr.port}/v1/chat/completions`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'hi' }] }),
  });

  const text = await res.text();
  server.close();

  let json: any = null;
  try { json = JSON.parse(text); } catch {}

  return { status: res.status, body: json, headers: res.headers };
}

describe('Proxy per-IP rate limiting (#35 item #6)', () => {
  const originalRpm = process.env.PROXY_RATE_LIMIT_RPM;

  beforeAll(() => {
    process.env.ENCRYPTION_KEY = '0'.repeat(64);
    initDb(':memory:');
  });

  afterAll(() => {
    if (originalRpm === undefined) delete process.env.PROXY_RATE_LIMIT_RPM;
    else process.env.PROXY_RATE_LIMIT_RPM = originalRpm;
  });

  it('returns 429 once the per-minute cap is exceeded', async () => {
    // Limiter reads the env at createApp() time, so set it before building.
    process.env.PROXY_RATE_LIMIT_RPM = '3';
    const app = createApp();

    // First 3 requests pass the limiter (they 401 on auth, but the limiter is
    // upstream of auth, so each one still counts against the window).
    for (let i = 0; i < 3; i++) {
      const res = await request(app);
      expect(res.status).not.toBe(429);
    }

    // The 4th trips the limit.
    const limited = await request(app);
    expect(limited.status).toBe(429);
    expect(limited.body.error.type).toBe('rate_limit_error');
    expect(limited.headers.get('retry-after')).toBeTruthy();
    expect(limited.headers.get('x-ratelimit-limit')).toBe('3');
  });

  it('does not rate-limit when PROXY_RATE_LIMIT_RPM=0', async () => {
    process.env.PROXY_RATE_LIMIT_RPM = '0';
    const app = createApp();

    for (let i = 0; i < 5; i++) {
      const res = await request(app);
      expect(res.status).not.toBe(429);
    }
  });

  it('keys the bucket on the socket peer, not a forged X-Forwarded-For, under TRUST_PROXY=true', async () => {
    // With `trust proxy` set to trust-everything, Express resolves req.ip to
    // the leftmost X-Forwarded-For entry — a header a direct caller can forge.
    // Spoofing a fresh address per request must not launder a fresh bucket:
    // all of them share the socket peer, so the cap still trips.
    process.env.PROXY_RATE_LIMIT_RPM = '3';
    process.env.TRUST_PROXY = 'true';
    try {
      const app = createApp();

      for (let i = 0; i < 3; i++) {
        const res = await request(app, { 'X-Forwarded-For': `10.0.0.${i + 1}` });
        expect(res.status).not.toBe(429);
      }
      const limited = await request(app, { 'X-Forwarded-For': '10.0.0.99' });
      expect(limited.status).toBe(429);
      expect(limited.body.error.type).toBe('rate_limit_error');
    } finally {
      delete process.env.TRUST_PROXY;
    }
  });
});
