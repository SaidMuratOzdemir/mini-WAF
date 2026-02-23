export interface Site {
    id: number;
    host: string;
    name: string;
    xss_enabled: boolean;
    sql_enabled: boolean;
    vt_enabled: boolean;
    health_status?: 'healthy' | 'unhealthy' | 'unknown';
}

export interface SiteCreate {
    host: string;
    name: string;
    xss_enabled: boolean;
    sql_enabled: boolean;
    vt_enabled: boolean;
}
