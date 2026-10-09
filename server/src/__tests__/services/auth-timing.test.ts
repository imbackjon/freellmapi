import { describe, it, expect, beforeAll, vi } from 'vitest';
import { initDb } from '../../db/index.js';
import { createUser, verifyCredentials } from '../../services/auth.js';

// The login endpoint must not be an account-existence oracle: an unknown email
// spends the same scrypt verification as a real one, so response timing cannot
// reveal whether an account exists.

vi.mock('../../lib/password.js', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../../lib/password.js')>();
  return {
    ...mod,
    verifyPassword: vi.fn(mod.verifyPassword),
  };
});

describe('login timing equalization', () => {
  beforeAll(() => {
    initDb(':memory:');
  });

  it('runs a scrypt verification even when the email does not exist', async () => {
    const { verifyPassword } = await import('../../lib/password.js');
    const spy = vi.mocked(verifyPassword);
    spy.mockClear();

    const result = verifyCredentials('nobody@example.com', 'not-a-real-password');

    expect(result).toBeNull();
    expect(spy).toHaveBeenCalledTimes(1);
    const [password, stored] = spy.mock.calls[0];
    expect(password).toBe('not-a-real-password');
    expect(stored.split('$')).toHaveLength(3);
    expect(stored.startsWith('scrypt$')).toBe(true);
  });

  it('verifies against the stored hash for an existing email', async () => {
    const { verifyPassword } = await import('../../lib/password.js');
    const spy = vi.mocked(verifyPassword);
    spy.mockClear();

    const user = createUser('existing@example.com', 'secret123');
    const result = verifyCredentials(user.email, 'wrong-password');

    expect(result).toBeNull();
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.calls[0][1]).not.toBeNull();
  });
});
