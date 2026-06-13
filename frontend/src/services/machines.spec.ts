import { beforeEach, describe, expect, it, vi } from 'vitest';

// Mock the axios boot module before importing the service under test.
vi.mock('boot/axios', () => ({
  api: { get: vi.fn() },
}));

import { api } from 'boot/axios';
import { listMachines } from './machines';

describe('listMachines', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
  });

  it('calls GET /machines with the given filters and returns the payload', async () => {
    const payload = { items: [], total: 0, page: 1, page_size: 50 };
    vi.mocked(api.get).mockResolvedValue({ data: payload });

    const result = await listMachines({ search: 'pc-01' });

    expect(api.get).toHaveBeenCalledWith('/machines', {
      params: { search: 'pc-01' },
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
