import { api } from 'boot/axios';

export interface StatsOverview {
  total: number;
  up_to_date: number;
  outdated: number;
  needs_verification: number;
  inactive: number;
  with_active_threats: number;
}

export async function getOverview(): Promise<StatsOverview> {
  const { data } = await api.get<StatsOverview>('/stats/overview');
  return data;
}
