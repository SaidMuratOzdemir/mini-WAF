import { useEffect, useState } from 'react';
import {
    Box,
    TextField,
    Button,
    FormControlLabel,
    Switch,
    Paper,
    Typography,
    Alert,
    Stack,
    MenuItem
} from '@mui/material';
import type { SiteCreate } from '../types/Site';
import { addSite } from '../api/sites';
import { fetchCertificates } from '../api/certificates';
import type { Certificate } from '../types/Certificate';

interface SiteFormProps {
    onSiteAdded: () => void;
    certRefreshToken?: number;
    currentUserRole?: 'admin' | 'super_admin' | null;
}

function isLikelyPrivateUpstream(rawUrl: string): boolean {
    try {
        const parsed = new URL(rawUrl.trim());
        const host = parsed.hostname.toLowerCase();
        if (host === 'localhost' || host.endsWith('.local')) return true;
        if (/^127\./.test(host)) return true;
        if (host === '::1') return true;
        if (/^10\./.test(host)) return true;
        if (/^192\.168\./.test(host)) return true;
        if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host)) return true;
        return false;
    } catch {
        return false;
    }
}

export function SiteForm({ onSiteAdded, certRefreshToken = 0, currentUserRole = null }: SiteFormProps) {
    const [certificates, setCertificates] = useState<Certificate[]>([]);
    const [formData, setFormData] = useState<SiteCreate>({
        host: '',
        name: '',
        upstream_url: '',
        is_active: true,
        preserve_host_header: false,
        enable_sni: true,
        websocket_enabled: true,
        sse_enabled: false,
        body_inspection_profile: 'default',
        client_max_body_size_mb: null,
        proxy_request_buffering: null,
        proxy_read_timeout_sec: 60,
        proxy_send_timeout_sec: 60,
        proxy_connect_timeout_sec: 10,
        proxy_redirect_mode: 'default',
        cookie_rewrite_enabled: false,
        waf_decision_mode: 'fail_close',
        tls_enabled: false,
        http_redirect_to_https: false,
        tls_certificate_id: null,
        upstream_tls_verify: true,
        upstream_tls_server_name_override: null,
        hsts_enabled: false,
        xss_enabled: true,
        sql_enabled: true,
        vt_enabled: false
    });
    const [error, setError] = useState<string>('');
    const upstreamIsHttps = formData.upstream_url.trim().toLowerCase().startsWith('https://');

    useEffect(() => {
        if (currentUserRole !== 'super_admin') {
            setCertificates([]);
            return;
        }
        const loadCertificates = async () => {
            try {
                const data = await fetchCertificates();
                setCertificates(data);
            } catch (e) {
                console.error('Failed to load certificates', e);
            }
        };
        void loadCertificates();
    }, [certRefreshToken, currentUserRole]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            // Validate required fields
            if (!formData.name.trim()) {
                throw new Error('Site name is required');
            }
            if (!formData.host.trim()) {
                throw new Error('Host field is required');
            }
            if (!formData.upstream_url.trim()) {
                throw new Error('Upstream URL is required');
            }
            if (formData.proxy_read_timeout_sec < 1 || formData.proxy_send_timeout_sec < 1 || formData.proxy_connect_timeout_sec < 1) {
                throw new Error('Proxy timeout değerleri 1 saniyeden büyük olmalıdır.');
            }
            if (formData.client_max_body_size_mb !== null && (formData.client_max_body_size_mb < 1 || formData.client_max_body_size_mb > 1024)) {
                throw new Error('Body size 1..1024 MB aralığında olmalıdır.');
            }
            if (currentUserRole !== 'super_admin' && isLikelyPrivateUpstream(formData.upstream_url)) {
                throw new Error('Private/LAN upstream tanımı yalnızca super_admin rolü için izinlidir.');
            }
            if (formData.tls_enabled && !formData.tls_certificate_id && certificates.length === 0) {
                throw new Error('TLS enabled requires a certificate (upload one or configure a default).');
            }

            await addSite(formData);
            onSiteAdded();

            // Reset form
            setFormData({
                host: '',
                name: '',
                upstream_url: '',
                is_active: true,
                preserve_host_header: false,
                enable_sni: true,
                websocket_enabled: true,
                sse_enabled: false,
                body_inspection_profile: 'default',
                client_max_body_size_mb: null,
                proxy_request_buffering: null,
                proxy_read_timeout_sec: 60,
                proxy_send_timeout_sec: 60,
                proxy_connect_timeout_sec: 10,
                proxy_redirect_mode: 'default',
                cookie_rewrite_enabled: false,
                waf_decision_mode: 'fail_close',
                tls_enabled: false,
                http_redirect_to_https: false,
                tls_certificate_id: null,
                upstream_tls_verify: true,
                upstream_tls_server_name_override: null,
                hsts_enabled: false,
                xss_enabled: true,
                sql_enabled: true,
                vt_enabled: false
            });
            setError('');
        } catch (e) {
            console.error('Form submission error:', e);
            setError(e instanceof Error ? e.message : 'Failed to add site');
        }
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, value } = e.target;
        const normalizedValue = name === 'tls_certificate_id'
            ? (value ? Number(value) : null)
            : name === 'client_max_body_size_mb'
                ? (value ? Number(value) : null)
                : name === 'proxy_read_timeout_sec' || name === 'proxy_send_timeout_sec' || name === 'proxy_connect_timeout_sec'
                    ? Number(value)
                    : name === 'proxy_request_buffering'
                        ? (value === '' ? null : value === 'true')
            : (name === 'upstream_tls_server_name_override' ? (value || null) : value);
        setFormData(prev => ({
            ...prev,
            [name]: normalizedValue
        }));
    };

    const handleSwitchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, checked } = e.target;
        setFormData(prev => {
            const next: SiteCreate = {
                ...prev,
                [name]: checked
            } as SiteCreate;

            if (name === 'tls_enabled' && !checked) {
                next.http_redirect_to_https = false;
                next.hsts_enabled = false;
                next.tls_certificate_id = null;
            }

            return next;
        });
    };

    return (
        <Paper elevation={2} sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
                Add New Protected Site
            </Typography>

            <Box component="form" onSubmit={handleSubmit} noValidate>
                <Stack spacing={3}>
                    {error && (
                        <Alert severity="error" sx={{ mb: 2 }}>
                            {error}
                        </Alert>
                    )}

                    <TextField
                        required
                        fullWidth
                        label="Site Name"
                        name="name"
                        value={formData.name}
                        onChange={handleChange}
                    />

                    <TextField
                        required
                        fullWidth
                        label="Host"
                        name="host"
                        value={formData.host}
                        onChange={handleChange}
                        placeholder="e.g., app.example.com"
                    />

                    <TextField
                        required
                        fullWidth
                        label="Upstream URL"
                        name="upstream_url"
                        value={formData.upstream_url}
                        onChange={handleChange}
                        placeholder="e.g., http://app-internal:8080"
                    />
                    {currentUserRole !== 'super_admin' && (
                        <Alert severity="info">
                            Private/LAN upstream hedefleri yalnızca super_admin rolü tarafından eklenebilir.
                        </Alert>
                    )}

                    <TextField
                        select
                        fullWidth
                        label="Body Inspection Profile"
                        name="body_inspection_profile"
                        value={formData.body_inspection_profile}
                        onChange={handleChange}
                    >
                        <MenuItem value="strict">strict</MenuItem>
                        <MenuItem value="default">default</MenuItem>
                        <MenuItem value="headers_only">headers_only</MenuItem>
                        <MenuItem value="upload_friendly">upload_friendly</MenuItem>
                    </TextField>

                    <Typography variant="subtitle1">TLS / HTTPS</Typography>

                    <TextField
                        select
                        fullWidth
                        label="TLS Certificate"
                        name="tls_certificate_id"
                        value={formData.tls_certificate_id ?? ''}
                        onChange={handleChange}
                        disabled={!formData.tls_enabled || currentUserRole !== 'super_admin'}
                        helperText={!formData.tls_enabled ? 'Enable TLS to select a certificate.' : 'Leave empty to use default certificate.'}
                    >
                        <MenuItem value="">
                            Use Default Certificate
                        </MenuItem>
                        {certificates.map((certificate) => (
                            <MenuItem key={certificate.id} value={certificate.id}>
                                {certificate.name}{certificate.is_default ? ' (default)' : ''}
                            </MenuItem>
                        ))}
                    </TextField>

                    <TextField
                        fullWidth
                        label="Upstream TLS SNI Override (Optional)"
                        name="upstream_tls_server_name_override"
                        value={formData.upstream_tls_server_name_override ?? ''}
                        onChange={handleChange}
                        disabled={!upstreamIsHttps}
                        placeholder="e.g., upstream.example.com"
                    />

                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.is_active}
                                    onChange={handleSwitchChange}
                                    name="is_active"
                                />
                            }
                            label="Active"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.preserve_host_header}
                                    onChange={handleSwitchChange}
                                    name="preserve_host_header"
                                />
                            }
                            label="Preserve Host Header"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.enable_sni}
                                    onChange={handleSwitchChange}
                                    name="enable_sni"
                                />
                            }
                            label="Enable SNI"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.websocket_enabled}
                                    onChange={handleSwitchChange}
                                    name="websocket_enabled"
                                />
                            }
                            label="WebSocket Enabled"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.sse_enabled}
                                    onChange={handleSwitchChange}
                                    name="sse_enabled"
                                />
                            }
                            label="SSE Enabled"
                        />
                    </Box>

                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.tls_enabled}
                                    onChange={handleSwitchChange}
                                    name="tls_enabled"
                                />
                            }
                            label="TLS Enabled"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.http_redirect_to_https}
                                    onChange={handleSwitchChange}
                                    name="http_redirect_to_https"
                                    disabled={!formData.tls_enabled}
                                />
                            }
                            label="HTTP -> HTTPS Redirect"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.upstream_tls_verify}
                                    onChange={handleSwitchChange}
                                    name="upstream_tls_verify"
                                    disabled={!upstreamIsHttps}
                                />
                            }
                            label="Upstream TLS Verify"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.hsts_enabled}
                                    onChange={handleSwitchChange}
                                    name="hsts_enabled"
                                    disabled={!formData.tls_enabled}
                                />
                            }
                            label="HSTS Enabled"
                        />
                    </Box>

                    <Typography variant="subtitle1">Advanced Proxy Settings</Typography>

                    <TextField
                        type="number"
                        fullWidth
                        label="Client Max Body Size (MB, empty=profile default)"
                        name="client_max_body_size_mb"
                        value={formData.client_max_body_size_mb ?? ''}
                        onChange={handleChange}
                        inputProps={{ min: 1, max: 1024 }}
                    />

                    <TextField
                        select
                        fullWidth
                        label="Proxy Request Buffering"
                        name="proxy_request_buffering"
                        value={formData.proxy_request_buffering === null ? '' : String(formData.proxy_request_buffering)}
                        onChange={handleChange}
                    >
                        <MenuItem value="">Profile Default</MenuItem>
                        <MenuItem value="true">on</MenuItem>
                        <MenuItem value="false">off</MenuItem>
                    </TextField>

                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <TextField
                            type="number"
                            fullWidth
                            label="Proxy Read Timeout (sec)"
                            name="proxy_read_timeout_sec"
                            value={formData.proxy_read_timeout_sec}
                            onChange={handleChange}
                            inputProps={{ min: 1, max: 3600 }}
                        />
                        <TextField
                            type="number"
                            fullWidth
                            label="Proxy Send Timeout (sec)"
                            name="proxy_send_timeout_sec"
                            value={formData.proxy_send_timeout_sec}
                            onChange={handleChange}
                            inputProps={{ min: 1, max: 3600 }}
                        />
                        <TextField
                            type="number"
                            fullWidth
                            label="Proxy Connect Timeout (sec)"
                            name="proxy_connect_timeout_sec"
                            value={formData.proxy_connect_timeout_sec}
                            onChange={handleChange}
                            inputProps={{ min: 1, max: 3600 }}
                        />
                    </Box>

                    <TextField
                        select
                        fullWidth
                        label="Proxy Redirect Mode"
                        name="proxy_redirect_mode"
                        value={formData.proxy_redirect_mode}
                        onChange={handleChange}
                    >
                        <MenuItem value="default">default</MenuItem>
                        <MenuItem value="off">off</MenuItem>
                        <MenuItem value="rewrite_to_public_host">rewrite_to_public_host</MenuItem>
                    </TextField>

                    <TextField
                        select
                        fullWidth
                        label="WAF Decision Mode"
                        name="waf_decision_mode"
                        value={formData.waf_decision_mode}
                        onChange={handleChange}
                    >
                        <MenuItem value="fail_close">fail_close</MenuItem>
                        <MenuItem value="fail_open">fail_open</MenuItem>
                    </TextField>

                    <Box sx={{ display: 'flex', gap: 2 }}>
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.cookie_rewrite_enabled}
                                    onChange={handleSwitchChange}
                                    name="cookie_rewrite_enabled"
                                />
                            }
                            label="Cookie Rewrite Enabled"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.xss_enabled}
                                    onChange={handleSwitchChange}
                                    name="xss_enabled"
                                />
                            }
                            label="XSS Protection"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.sql_enabled}
                                    onChange={handleSwitchChange}
                                    name="sql_enabled"
                                />
                            }
                            label="SQL Injection Protection"
                        />

                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.vt_enabled}
                                    onChange={handleSwitchChange}
                                    name="vt_enabled"
                                />
                            }
                            label="Enable VirusTotal Scan"
                        />
                    </Box>

                    <Button
                        type="submit"
                        variant="contained"
                        color="primary"
                        size="large"
                    >
                        Add Site
                    </Button>
                </Stack>
            </Box>
        </Paper>
    );
}
