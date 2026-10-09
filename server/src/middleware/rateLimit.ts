import type { Request, Response, NextFunction } from 'express';

// Per-IP fixed-window rate limiter for the public /v1 proxy (#35, item #6).
//
// The /v1 surface authenticates with the unified API key but has no password
// login like the dashboard does, so without this an attacker who can reach the
// server could brute-force the key or flood upstream providers. This caps how
// many requests a single client IP can make per minute and returns a standard
// OpenAI-shaped 429 once the cap is exceeded.
//
// FreeLLMAPI is a single-user tool, so the default ceiling is generous. Tune it
// with PROXY_RATE_LIMIT_RPM (requests per minute per IP); set it to 0 to turn
// rate limiting off entirely.

const WINDOW_MS = 60_000;
const DEFAULT_RPM = 120;
// Bound the IP map so a flood of distinct (e.g. spoofed) source addresses can't
// grow it without limit; expired entries are pruned opportunistically.
const MAX_TRACKED_IPS = 10_000;

interface WindowState {
  count: number;
  resetAt: number;
}

function parseLimit(): number {
  const raw = process.env.PROXY_RATE_LIMIT_RPM;
  if (raw === undefined || raw.trim() === '') return DEFAULT_RPM;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return DEFAULT_RPM;
  return Math.floor(n);
}

/**
 * The address that owns a rate-limit bucket.
 *
 * Express's `req.ip` honours the configured trust-proxy chain, but with
 * `TRUST_PROXY=true` (trust every hop) it resolves to the LEFTMOST
 * X-Forwarded-For entry — a header any direct caller can forge, which would
 * let one attacker launder unlimited distinct buckets and walk straight
 * through every per-IP cap. The socket peer is the one address a caller
 * cannot spoof, so the trust-all mode keys buckets on it. Behind a real
 * reverse proxy that means every caller shares the proxy's bucket and the
 * limit caps total attempts rather than per-client — exactly the
 * brute-force protection these limiters exist to provide. Hop-count and
 * address-list trust settings keep the precise first-untrusted address from
 * `req.ip`.
 */
function rateLimitClientIp(req: Request): string {
  const fallback = req.socket.remoteAddress ?? 'unknown';
  const ip = req.app.get('trust proxy') === true ? fallback : (req.ip ?? fallback);
  // Normalize IPv4-mapped IPv6 ("::ffff:192.168.0.5" -> "192.168.0.5") so the
  // two spellings of one address share a bucket.
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

export function createProxyRateLimiter(rpmLimit?: number) {
  const limit = rpmLimit !== undefined ? Math.floor(Math.max(0, rpmLimit)) : parseLimit();
  const windows = new Map<string, WindowState>();

  return function proxyRateLimit(req: Request, res: Response, next: NextFunction): void {
    if (limit === 0) {
      next();
      return;
    }

    const now = Date.now();
    const ip = rateLimitClientIp(req);

    let state = windows.get(ip);
    if (!state || now >= state.resetAt) {
      state = { count: 0, resetAt: now + WINDOW_MS };
      windows.set(ip, state);
    }
    state.count += 1;

    if (windows.size > MAX_TRACKED_IPS) {
      for (const [key, value] of windows) {
        if (now >= value.resetAt) windows.delete(key);
      }
    }

    res.setHeader('X-RateLimit-Limit', String(limit));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, limit - state.count)));
    res.setHeader('X-RateLimit-Reset', String(Math.ceil(state.resetAt / 1000)));

    if (state.count > limit) {
      const retryAfter = Math.max(1, Math.ceil((state.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      res.status(429).json({
        error: {
          message: `Rate limit exceeded: more than ${limit} requests per minute. Retry in ${retryAfter}s.`,
          type: 'rate_limit_error',
        },
      });
      return;
    }

    next();
  };
}

// Per-IP fixed-window rate limiter for the /api/* admin surface.
//
// This is a flood guard, not the brute-force guard: dashboard login already has
// its own per-email lockout (routes/auth.ts), and the one admin endpoint that
// verifies a password — GET /api/keys/export — gets its own much tighter
// limiter mounted in app.ts. The broad cap therefore has to clear normal
// dashboard traffic with room to spare. Opening the dashboard fans out across
// keys, health, models, analytics, settings and profiles, and several of those
// poll, so a single user legitimately spends dozens of requests a minute.
//
// Tune with ADMIN_RATE_LIMIT_RPM (requests per minute per IP); 0 disables it.
const ADMIN_DEFAULT_RPM = 600;

function parseAdminLimit(): number {
  const raw = process.env.ADMIN_RATE_LIMIT_RPM;
  if (raw === undefined || raw.trim() === '') return ADMIN_DEFAULT_RPM;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return ADMIN_DEFAULT_RPM;
  return Math.floor(n);
}

export function createAdminRateLimiter(rpm?: number) {
  const limit = rpm !== undefined ? Math.floor(Math.max(0, rpm)) : parseAdminLimit();
  const windows = new Map<string, WindowState>();

  return function adminRateLimit(req: Request, res: Response, next: NextFunction): void {
    if (limit === 0) {
      next();
      return;
    }

    const now = Date.now();
    const ip = rateLimitClientIp(req);

    let state = windows.get(ip);
    if (!state || now >= state.resetAt) {
      state = { count: 0, resetAt: now + WINDOW_MS };
      windows.set(ip, state);
    }
    state.count += 1;

    if (windows.size > MAX_TRACKED_IPS) {
      for (const [key, value] of windows) {
        if (now >= value.resetAt) windows.delete(key);
      }
    }

    res.setHeader('X-RateLimit-Limit', String(limit));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, limit - state.count)));
    res.setHeader('X-RateLimit-Reset', String(Math.ceil(state.resetAt / 1000)));

    if (state.count > limit) {
      const retryAfter = Math.max(1, Math.ceil((state.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfter));
      res.status(429).json({
        error: {
          message: `Rate limit exceeded: more than ${limit} requests per minute. Retry in ${retryAfter}s.`,
          type: 'rate_limit_error',
        },
      });
      return;
    }

    next();
  };
}
