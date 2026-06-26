import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('boot/axios', () => ({
  api: { get: vi.fn(), post: vi.fn() },
}));

import { api } from 'boot/axios';
import { getMe, login } from './auth';

describe('login', () => {
  beforeEach(() => {
    vi.mocked(api.post).mockReset();
  });

  it('posts form-encoded credentials and returns the token', async () => {
    vi.mocked(api.post).mockResolvedValue({
      data: { access_token: 'jwt-123', token_type: 'bearer' },
    });

    const result = await login('admin@test.local', 'secret');

    expect(result.access_token).toBe('jwt-123');
    const [url, body] = vi.mocked(api.post).mock.calls[0]!;
    expect(url).toBe('/auth/login');
    expect(body).toBeInstanceOf(URLSearchParams);
    expect((body as URLSearchParams).get('username')).toBe('admin@test.local');
    expect((body as URLSearchParams).get('password')).toBe('secret');
  });
});

describe('getMe', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
  });

  it('fetches the current user', async () => {
    const user = { id: 'u-1', email: 'admin@test.local', full_name: null, role: 'admin' };
    vi.mocked(api.get).mockResolvedValue({ data: user });

    const result = await getMe();

    expect(api.get).toHaveBeenCalledWith('/auth/me');
    expect(result).toEqual(user);
  });
});
