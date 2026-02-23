import { apiFetch } from './client';

export interface CurrentUser {
  id: number;
  username: string;
  is_admin: boolean;
  role: 'admin' | 'super_admin';
}

export const fetchCurrentUser = async (): Promise<CurrentUser> => apiFetch('/auth/me');
