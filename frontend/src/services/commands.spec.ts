import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('boot/axios', () => ({
  api: { get: vi.fn(), post: vi.fn() },
}));

import { api } from 'boot/axios';
import { createCommands, listCommands } from './commands';

describe('createCommands', () => {
  beforeEach(() => {
    vi.mocked(api.post).mockReset();
  });

  it('posts the payload and returns the created ids', async () => {
    const payload = { created: ['c-1', 'c-2'], count: 2 };
    vi.mocked(api.post).mockResolvedValue({ data: payload });

    const result = await createCommands({ type: 'quick_scan', machine_ids: ['m-1', 'm-2'] });

    expect(api.post).toHaveBeenCalledWith('/commands', {
      type: 'quick_scan',
      machine_ids: ['m-1', 'm-2'],
    });
    expect(result).toEqual(payload);
  });
});

describe('listCommands', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
  });

  it('lists commands filtered by machine and status', async () => {
    const payload = { items: [], total: 0, page: 1, page_size: 50 };
    vi.mocked(api.get).mockResolvedValue({ data: payload });

    const result = await listCommands({ machine_id: 'm-1', status: 'pending' });

    expect(api.get).toHaveBeenCalledWith('/commands', {
      params: { machine_id: 'm-1', status: 'pending' },
    });
    expect(result).toEqual(payload);
  });

  it('passes no params by default', async () => {
    vi.mocked(api.get).mockResolvedValue({
      data: { items: [], total: 0, page: 1, page_size: 50 },
    });

    await listCommands();

    expect(api.get).toHaveBeenCalledWith('/commands', { params: {} });
  });
});
