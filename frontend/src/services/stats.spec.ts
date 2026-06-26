import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('boot/axios', () => ({
  api: { get: vi.fn() },
}));

import { api } from 'boot/axios';
import { getOverview } from './stats';

describe('getOverview', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset();
  });

  it('fetches the fleet KPIs', async () => {
    const payload = {
      total: 10,
      up_to_date: 7,
      outdated: 3,
      needs_verification: 1,
      inactive: 2,
      with_active_threats: 1,
    };
    vi.mocked(api.get).mockResolvedValue({ data: payload });

    const result = await getOverview();

    expect(api.get).toHaveBeenCalledWith('/stats/overview');
    expect(result).toEqual(payload);
  });
});
