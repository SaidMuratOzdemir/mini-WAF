import { apiFetch } from './client';
import type {
  ForwardProxyStatus,
  OutboundDestinationRule,
  OutboundDestinationRuleCreate,
  OutboundProxyProfile,
  OutboundProxyProfileCreate,
} from '../types/OutboundProxy';

export const fetchOutboundProfiles = async (): Promise<OutboundProxyProfile[]> =>
  apiFetch('/forward-proxy/profiles');

export const createOutboundProfile = async (
  payload: OutboundProxyProfileCreate,
): Promise<OutboundProxyProfile> => apiFetch('/forward-proxy/profiles', {
  method: 'POST',
  body: JSON.stringify(payload),
});

export const updateOutboundProfile = async (
  profileId: number,
  payload: OutboundProxyProfileCreate,
): Promise<OutboundProxyProfile> => apiFetch(`/forward-proxy/profiles/${profileId}`, {
  method: 'PUT',
  body: JSON.stringify(payload),
});

export const deleteOutboundProfile = async (profileId: number): Promise<void> =>
  apiFetch(`/forward-proxy/profiles/${profileId}`, { method: 'DELETE' });

export const fetchOutboundRules = async (profileId: number): Promise<OutboundDestinationRule[]> =>
  apiFetch(`/forward-proxy/profiles/${profileId}/rules`);

export const createOutboundRule = async (
  profileId: number,
  payload: OutboundDestinationRuleCreate,
): Promise<OutboundDestinationRule> => apiFetch(`/forward-proxy/profiles/${profileId}/rules`, {
  method: 'POST',
  body: JSON.stringify(payload),
});

export const updateOutboundRule = async (
  ruleId: number,
  payload: OutboundDestinationRuleCreate,
): Promise<OutboundDestinationRule> => apiFetch(`/forward-proxy/rules/${ruleId}`, {
  method: 'PUT',
  body: JSON.stringify(payload),
});

export const deleteOutboundRule = async (ruleId: number): Promise<void> =>
  apiFetch(`/forward-proxy/rules/${ruleId}`, { method: 'DELETE' });

export const applyOutboundProxyConfig = async (): Promise<Record<string, unknown>> =>
  apiFetch('/forward-proxy/apply', { method: 'POST' });

export const fetchForwardProxyStatus = async (): Promise<ForwardProxyStatus> =>
  apiFetch('/forward-proxy/status');
