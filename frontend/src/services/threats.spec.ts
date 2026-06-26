import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('boot/axios', () => ({
  api: { get: vi.fn() },
}));

import { api } from 'boot/axios';
import { listThreats } from './threats';

describe('listThreats', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
  });

  it('lists threats filtered by machine and severity', async () => {
    const payload = { items: [], total: 0, page: 1, page_size: 50 };
    vi.mocked(api.get).mockResolvedValue({ data: payload });

    const result = await listThreats({ machine_id: 'm-1', severity: 'high' });

    expect(api.get).toHaveBeenCalledWith('/threats', {
      params: { machine_id: 'm-1', severity: 'high' },
    });
    expect(result).toEqual(payload);
  });

  it('passes no params by default', async () => {
    vi.mocked(api.get).mockResolvedValue({
      data: { items: [], total: 0, page: 1, page_size: 50 },
    });

    await listThreats();

    expect(api.get).toHaveBeenCalledWith('/threats', { params: {} });
  });
});
