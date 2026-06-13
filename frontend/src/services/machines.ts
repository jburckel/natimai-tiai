import { api } from 'boot/axios';

export interface Machine {
  id: string;
  machine_uuid: string;
  hostname: string | null;
  domain: string | null;
  os_version: string | null;
  agent_version: string | null;
  is_up_to_date: boolean | null;
  signature_version: string | null;
  last_seen: string;
}

export interface MachineList {
  items: Machine[];
  total: number;
  page: number;
  page_size: number;
}

export async function listMachines(
  params: {
    search?: string;
    domain?: string;
    page?: number;
    page_size?: number;
  } = {},
): Promise<MachineList> {
  const { data } = await api.get<MachineList>('/machines', { params });
  return data;
}
