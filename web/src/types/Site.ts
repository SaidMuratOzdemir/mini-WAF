export interface Site {
    id: number;
    host: string;
    name: string;
    upstream_url: string;
    is_active: boolean;
    preserve_host_header: boolean;
    enable_sni: boolean;
    websocket_enabled: boolean;
    body_inspection_profile: string;
    tls_enabled: boolean;
    http_redirect_to_https: boolean;
    tls_certificate_id: number | null;
    upstream_tls_verify: boolean;
    upstream_tls_server_name_override: string | null;
    hsts_enabled: boolean;
    xss_enabled: boolean;
    sql_enabled: boolean;
    vt_enabled: boolean;
    health_status?: 'healthy' | 'unhealthy' | 'unknown';
}

export interface SiteCreate {
    host: string;
    name: string;
    upstream_url: string;
    is_active: boolean;
    preserve_host_header: boolean;
    enable_sni: boolean;
    websocket_enabled: boolean;
    body_inspection_profile: string;
    tls_enabled: boolean;
    http_redirect_to_https: boolean;
    tls_certificate_id: number | null;
    upstream_tls_verify: boolean;
    upstream_tls_server_name_override: string | null;
    hsts_enabled: boolean;
    xss_enabled: boolean;
    sql_enabled: boolean;
    vt_enabled: boolean;
}
