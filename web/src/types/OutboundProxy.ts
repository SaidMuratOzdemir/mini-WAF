export type ForwardProxyAction = 'allow' | 'deny';
export type ForwardProxyRuleType = 'domain_exact' | 'domain_suffix' | 'host_exact' | 'cidr' | 'port';

export interface OutboundProxyProfile {
  id: number;
  name: string;
  listen_port: number;
  is_enabled: boolean;
  require_auth: boolean;
  allow_connect_ports: string;
  allowed_client_cidrs: string | null;
  default_action: ForwardProxyAction;
  created_at: string;
  updated_at: string;
}

export interface OutboundProxyProfileCreate {
  name: string;
  listen_port: number;
  is_enabled: boolean;
  require_auth: boolean;
  allow_connect_ports: string;
  allowed_client_cidrs: string | null;
  default_action: ForwardProxyAction;
}

export interface OutboundDestinationRule {
  id: number;
  profile_id: number;
  action: ForwardProxyAction;
  rule_type: ForwardProxyRuleType;
  value: string;
  priority: number;
  is_enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface OutboundDestinationRuleCreate {
  action: ForwardProxyAction;
  rule_type: ForwardProxyRuleType;
  value: string;
  priority: number;
  is_enabled: boolean;
}

export interface ForwardProxyStatus {
  active_profile_id: number | null;
  active_profile_name: string | null;
  active_rule_count: number;
  config_path: string;
  validation: {
    ok: boolean;
    command: string[];
    returncode: number;
    stdout: string;
    stderr: string;
  };
}
