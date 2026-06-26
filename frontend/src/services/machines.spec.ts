import { beforeEach, describe, expect, it, vi } from 'vitest';

// Mock the axios boot module before importing the service under test.
vi.mock('boot/axios', () => ({
  api: { get: vi.fn(), post: vi.fn() },
}));

import { api } from 'boot/axios';
import { getMachine, listMachines, revokeToken } from './machines';

describe('listMachines', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
  });

  it('calls GET /machines with the given filters and returns the payload', async () => {
    const payload = { items: [], total: 0, page: 1, page_size: 50 };
    vi.mocked(api.get).mockResolvedValue({ data: payload });

    const result = await listMachines({ search: 'pc-01', status: 'outdated' });

    expect(api.get).toHaveBeenCalledWith('/machines', {
      params: { search: 'pc-01', status: 'outdated' },
    });
    expect(result).toEqual(payload);
  });

  it('passes no params when called with no arguments', async () => {
    vi.mocked(api.get).mockResolvedValue({
      data: { items: [], total: 0, page: 1, page_size: 50 },
    });

    await listMachines();

    expect(api.get).toHaveBeenCalledWith('/machines', { params: {} });
  });
});

describe('getMachine', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
  });

  it('fetches a single machine by id', async () => {
    const detail = { id: 'm-1', hostname: 'PC-01' };
    vi.mocked(api.get).mockResolvedValue({ data: detail });

    const result = await getMachine('m-1');

    expect(api.get).toHaveBeenCalledWith('/machines/m-1');
    expect(result).toEqual(detail);
  });
});

describe('revokeToken', () => {
  beforeEach(() => {
    vi.mocked(api.post).mockReset();
  });

  it('posts to the revoke-token endpoint', async () => {
    vi.mocked(api.post).mockResolvedValue({ data: { status: 'revoked' } });

    await revokeToken('m-9');

    expect(api.post).toHaveBeenCalledWith('/machines/m-9/revoke-token');
  });
});
