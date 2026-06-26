import { api } from 'boot/axios';

export interface Token {
  access_token: string;
  token_type: string;
}

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
}

export async function login(email: string, password: string): Promise<Token> {
  // OAuth2 password flow: the backend expects form-encoded username/password.
  const form = new URLSearchParams();
  form.append('username', email);
  form.append('password', password);
  const { data } = await api.post<Token>('/auth/login', form);
  return data;
}

export async function getMe(): Promise<User> {
  const { data } = await api.get<User>('/auth/me');
  return data;
}
