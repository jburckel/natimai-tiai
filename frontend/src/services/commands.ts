import { api } from 'boot/axios';

export type CommandType = 'quick_scan' | 'full_scan' | 'update_signatures';

export type CommandStatus =
  | 'pending'
  | 'delivered'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'expired';

export interface CreateCommandsPayload {
  type: CommandType;
  ttl_minutes?: number;
  // Exactly one target must be provided.
  machine_ids?: string[];
  target_all?: boolean;
  target_domain?: string;
  target_status?: string;
}

export interface CreateCommandsResponse {
  created: string[];
  count: number;
}

export interface Command {
  id: string;
  machine_id: string;
  type: string;
  status: string;
  created_by: string | null;
  created_at: string;
  expires_at: string;
  delivered_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  result_output: string | null;
  error: string | null;
}

export interface CommandList {
  items: Command[];
  total: number;
  page: number;
  page_size: number;
}

export interface ListCommandsParams {
  status?: CommandStatus;
  machine_id?: string;
  page?: number;
  page_size?: number;
}

export async function createCommands(
  payload: CreateCommandsPayload,
): Promise<CreateCommandsResponse> {
  const { data } = await api.post<CreateCommandsResponse>('/commands', payload);
  return data;
}

export async function listCommands(params: ListCommandsParams = {}): Promise<CommandList> {
  const { data } = await api.get<CommandList>('/commands', { params });
  return data;
}
