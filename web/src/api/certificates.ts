import { apiFetch } from './client';
import type { Certificate } from '../types/Certificate';

export const fetchCertificates = async (): Promise<Certificate[]> => apiFetch('/certificates');

export const uploadCertificate = async (formData: FormData): Promise<Certificate> =>
  apiFetch('/certificates/upload', { method: 'POST', body: formData });

export const setDefaultCertificate = async (id: number): Promise<Certificate> =>
  apiFetch(`/certificates/${id}/default`, { method: 'PUT' });

export const deleteCertificate = async (id: number): Promise<void> =>
  apiFetch(`/certificates/${id}`, { method: 'DELETE' });
