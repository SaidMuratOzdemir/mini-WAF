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
    xss_enabled: boolean;
    sql_enabled: boolean;
    vt_enabled: boolean;
}
