import { beforeEach, describe, expect, it, vi } from 'vitest';

// Hoisted with the mock below, which runs before the imports.
const { post } = vi.hoisted(() => ({ post: vi.fn() }));
vi.mock('axios', () => ({
  default: { create: () => ({ post }) },
}));

import { endSession, getAccessToken, renewAccessToken, setAccessToken } from './session';

function httpError(status: number) {
  return Object.assign(new Error(String(status)), { response: { status } });
}

describe('renewAccessToken', () => {
  beforeEach(() => {
    post.mockReset();
    setAccessToken(null);
  });

  it('keeps the renewed token in memory', async () => {
    post.mockResolvedValueOnce({ data: { access_token: 'fresh' } });
    expect(await renewAccessToken()).toBe('fresh');
    expect(getAccessToken()).toBe('fresh');
  });

  it('shares one request between concurrent callers', async () => {
    // Ten calls failing with 401 at once must spend one refresh token, not
    // ten — the other nine would read as reuse and end the session.
    post.mockResolvedValueOnce({ data: { access_token: 'shared' } });
    const results = await Promise.all([renewAccessToken(), renewAccessToken()]);
    expect(results).toEqual(['shared', 'shared']);
    expect(post).toHaveBeenCalledTimes(1);
  });

  it('retries once when another tab renewed first', async () => {
    vi.useFakeTimers();
    post
      .mockRejectedValueOnce(httpError(409))
      .mockResolvedValueOnce({ data: { access_token: 'after-race' } });
    const pending = renewAccessToken();
    await vi.advanceTimersByTimeAsync(500);
    expect(await pending).toBe('after-race');
    expect(post).toHaveBeenCalledTimes(2);
    vi.useRealTimers();
  });

  it('reports the end of the session as null', async () => {
    setAccessToken('stale');
    post.mockRejectedValueOnce(httpError(401));
    expect(await renewAccessToken()).toBeNull();
    expect(getAccessToken()).toBeNull();
  });
});

describe('endSession', () => {
  it('forgets the token even when the server is unreachable', async () => {
    setAccessToken('live');
    post.mockRejectedValueOnce(new Error('network'));
    await endSession();
    expect(getAccessToken()).toBeNull();
    expect(post).toHaveBeenCalledWith('/auth/logout');
  });
});
