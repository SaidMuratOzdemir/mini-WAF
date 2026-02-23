import { useState, useEffect } from 'react';
import {
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    Button,
    TextField,
    FormControlLabel,
    Switch,
    Box,
    Alert,
    CircularProgress,
    MenuItem
} from '@mui/material';
import type { Site, SiteCreate } from '../types/Site';
import { updateSite } from '../api/sites';
import type { Certificate } from '../types/Certificate';
import { fetchCertificates } from '../api/certificates';
import { useAuth } from '../context/AuthContext';

interface EditSiteModalProps {
    open: boolean;
    site: Site | null;
    onClose: () => void;
    onSuccess: () => void;
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

const EditSiteModal = ({ open, site, onClose, onSuccess }: EditSiteModalProps) => {
    const { role } = useAuth();
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
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Reset form when site changes
    useEffect(() => {
        if (role !== 'super_admin') {
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
    }, [role]);

    useEffect(() => {
        if (site) {
            setFormData({
                host: site.host,
                name: site.name,
                upstream_url: site.upstream_url,
                is_active: site.is_active,
                preserve_host_header: site.preserve_host_header,
                enable_sni: site.enable_sni,
                websocket_enabled: site.websocket_enabled,
                sse_enabled: site.sse_enabled,
                body_inspection_profile: site.body_inspection_profile,
                client_max_body_size_mb: site.client_max_body_size_mb,
                proxy_request_buffering: site.proxy_request_buffering,
                proxy_read_timeout_sec: site.proxy_read_timeout_sec,
                proxy_send_timeout_sec: site.proxy_send_timeout_sec,
                proxy_connect_timeout_sec: site.proxy_connect_timeout_sec,
                proxy_redirect_mode: site.proxy_redirect_mode,
                cookie_rewrite_enabled: site.cookie_rewrite_enabled,
                waf_decision_mode: site.waf_decision_mode,
                tls_enabled: site.tls_enabled,
                http_redirect_to_https: site.http_redirect_to_https,
                tls_certificate_id: site.tls_certificate_id,
                upstream_tls_verify: site.upstream_tls_verify,
                upstream_tls_server_name_override: site.upstream_tls_server_name_override,
                hsts_enabled: site.hsts_enabled,
                xss_enabled: site.xss_enabled,
                sql_enabled: site.sql_enabled,
                vt_enabled: site.vt_enabled
            });
        }
        setError(null);
    }, [site]);

    const handleInputChange = (field: keyof SiteCreate) => (
        event: React.ChangeEvent<HTMLInputElement>
    ) => {
        const rawValue = event.target.type === 'checkbox'
            ? event.target.checked
            : event.target.value;
        const value = field === 'tls_certificate_id'
            ? (rawValue ? Number(rawValue) : null)
            : field === 'client_max_body_size_mb'
                ? (rawValue ? Number(rawValue) : null)
                : field === 'proxy_read_timeout_sec' || field === 'proxy_send_timeout_sec' || field === 'proxy_connect_timeout_sec'
                    ? Number(rawValue)
                    : field === 'proxy_request_buffering'
                        ? (rawValue === '' ? null : rawValue === 'true')
                        : (field === 'upstream_tls_server_name_override' ? (rawValue || null) : rawValue);

        setFormData(prev => {
            const next: SiteCreate = {
                ...prev,
                [field]: value
            } as SiteCreate;
            if (field === 'tls_enabled' && value === false) {
                next.http_redirect_to_https = false;
                next.hsts_enabled = false;
                next.tls_certificate_id = null;
            }
            return next;
        });
    };

    const handleSubmit = async () => {
        if (!site) return;

        if (!formData.name.trim()) {
            setError('Site name is required.');
            return;
        }
        if (!formData.host.trim()) {
            setError('Host field is required.');
            return;
        }
        if (!formData.upstream_url.trim()) {
            setError('Upstream URL is required.');
            return;
        }
        if (
            formData.proxy_read_timeout_sec < 1
            || formData.proxy_send_timeout_sec < 1
            || formData.proxy_connect_timeout_sec < 1
        ) {
            setError('Proxy timeout değerleri 1 saniyeden büyük olmalıdır.');
            return;
        }
        if (
            formData.client_max_body_size_mb !== null
            && (formData.client_max_body_size_mb < 1 || formData.client_max_body_size_mb > 1024)
        ) {
            setError('Body size 1..1024 MB aralığında olmalıdır.');
            return;
        }
        if (role !== 'super_admin' && isLikelyPrivateUpstream(formData.upstream_url)) {
            setError('Private/LAN upstream tanımı yalnızca super_admin rolü için izinlidir.');
            return;
        }
        if (formData.tls_enabled && !formData.tls_certificate_id && certificates.length === 0) {
            setError('TLS enabled requires a certificate (upload one or configure a default).');
            return;
        }

        setLoading(true);
        setError(null);

        try {
            await updateSite(site.id, formData);
            onSuccess();
            onClose();
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Update failed');
        } finally {
            setLoading(false);
        }
    };

    const handleClose = () => {
        if (!loading) {
            onClose();
        }
    };
    const upstreamIsHttps = formData.upstream_url.trim().toLowerCase().startsWith('https://');

    return (
        <Dialog open={open} onClose={handleClose} maxWidth="md" fullWidth>
            <DialogTitle>
                Edit Site: {site?.name}
            </DialogTitle>
            <DialogContent>
                {error && (
                    <Alert severity="error" sx={{ mb: 2 }}>
                        {error}
                    </Alert>
                )}

                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
                    <TextField
                        label="Site Name"
                        value={formData.name}
                        onChange={handleInputChange('name')}
                        fullWidth
                        required
                        disabled={loading}
                    />

                    <TextField
                        label="Host"
                        value={formData.host}
                        onChange={handleInputChange('host')}
                        fullWidth
                        required
                        disabled={loading}
                        placeholder="e.g., app.example.com"
                    />

                    <TextField
                        label="Upstream URL"
                        value={formData.upstream_url}
                        onChange={handleInputChange('upstream_url')}
                        fullWidth
                        required
                        disabled={loading}
                        placeholder="e.g., http://app-internal:8080"
                    />

                    <TextField
                        select
                        label="Body Inspection Profile"
                        value={formData.body_inspection_profile}
                        onChange={handleInputChange('body_inspection_profile')}
                        fullWidth
                        required
                        disabled={loading}
                    >
                        <MenuItem value="strict">strict</MenuItem>
                        <MenuItem value="default">default</MenuItem>
                        <MenuItem value="headers_only">headers_only</MenuItem>
                        <MenuItem value="upload_friendly">upload_friendly</MenuItem>
                    </TextField>

                    <TextField
                        select
                        fullWidth
                        label="TLS Certificate"
                        value={formData.tls_certificate_id ?? ''}
                        onChange={handleInputChange('tls_certificate_id')}
                        disabled={loading || !formData.tls_enabled || role !== 'super_admin'}
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
                        label="Upstream TLS SNI Override (Optional)"
                        value={formData.upstream_tls_server_name_override ?? ''}
                        onChange={handleInputChange('upstream_tls_server_name_override')}
                        fullWidth
                        disabled={loading || !upstreamIsHttps}
                        placeholder="e.g., upstream.example.com"
                    />

                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.is_active}
                                    onChange={handleInputChange('is_active')}
                                    disabled={loading}
                                />
                            }
                            label="Active"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.preserve_host_header}
                                    onChange={handleInputChange('preserve_host_header')}
                                    disabled={loading}
                                />
                            }
                            label="Preserve Host Header"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.enable_sni}
                                    onChange={handleInputChange('enable_sni')}
                                    disabled={loading}
                                />
                            }
                            label="Enable SNI"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.websocket_enabled}
                                    onChange={handleInputChange('websocket_enabled')}
                                    disabled={loading}
                                />
                            }
                            label="WebSocket Enabled"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.sse_enabled}
                                    onChange={handleInputChange('sse_enabled')}
                                    disabled={loading}
                                />
                            }
                            label="SSE Enabled"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.tls_enabled}
                                    onChange={handleInputChange('tls_enabled')}
                                    disabled={loading}
                                />
                            }
                            label="TLS Enabled"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.http_redirect_to_https}
                                    onChange={handleInputChange('http_redirect_to_https')}
                                    disabled={loading || !formData.tls_enabled}
                                />
                            }
                            label="HTTP -> HTTPS Redirect"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.upstream_tls_verify}
                                    onChange={handleInputChange('upstream_tls_verify')}
                                    disabled={loading || !upstreamIsHttps}
                                />
                            }
                            label="Upstream TLS Verify"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.hsts_enabled}
                                    onChange={handleInputChange('hsts_enabled')}
                                    disabled={loading || !formData.tls_enabled}
                                />
                            }
                            label="HSTS Enabled"
                        />
                    </Box>

                    <TextField
                        type="number"
                        fullWidth
                        label="Client Max Body Size (MB, empty=profile default)"
                        value={formData.client_max_body_size_mb ?? ''}
                        onChange={handleInputChange('client_max_body_size_mb')}
                        disabled={loading}
                        inputProps={{ min: 1, max: 1024 }}
                    />

                    <TextField
                        select
                        fullWidth
                        label="Proxy Request Buffering"
                        value={formData.proxy_request_buffering === null ? '' : String(formData.proxy_request_buffering)}
                        onChange={handleInputChange('proxy_request_buffering')}
                        disabled={loading}
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
                            value={formData.proxy_read_timeout_sec}
                            onChange={handleInputChange('proxy_read_timeout_sec')}
                            disabled={loading}
                            inputProps={{ min: 1, max: 3600 }}
                        />
                        <TextField
                            type="number"
                            fullWidth
                            label="Proxy Send Timeout (sec)"
                            value={formData.proxy_send_timeout_sec}
                            onChange={handleInputChange('proxy_send_timeout_sec')}
                            disabled={loading}
                            inputProps={{ min: 1, max: 3600 }}
                        />
                        <TextField
                            type="number"
                            fullWidth
                            label="Proxy Connect Timeout (sec)"
                            value={formData.proxy_connect_timeout_sec}
                            onChange={handleInputChange('proxy_connect_timeout_sec')}
                            disabled={loading}
                            inputProps={{ min: 1, max: 3600 }}
                        />
                    </Box>

                    <TextField
                        select
                        fullWidth
                        label="Proxy Redirect Mode"
                        value={formData.proxy_redirect_mode}
                        onChange={handleInputChange('proxy_redirect_mode')}
                        disabled={loading}
                    >
                        <MenuItem value="default">default</MenuItem>
                        <MenuItem value="off">off</MenuItem>
                        <MenuItem value="rewrite_to_public_host">rewrite_to_public_host</MenuItem>
                    </TextField>

                    <TextField
                        select
                        fullWidth
                        label="WAF Decision Mode"
                        value={formData.waf_decision_mode}
                        onChange={handleInputChange('waf_decision_mode')}
                        disabled={loading}
                    >
                        <MenuItem value="fail_close">fail_close</MenuItem>
                        <MenuItem value="fail_open">fail_open</MenuItem>
                    </TextField>

                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.cookie_rewrite_enabled}
                                    onChange={handleInputChange('cookie_rewrite_enabled')}
                                    disabled={loading}
                                />
                            }
                            label="Cookie Rewrite Enabled"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.xss_enabled}
                                    onChange={handleInputChange('xss_enabled')}
                                    disabled={loading}
                                />
                            }
                            label="XSS Protection"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.sql_enabled}
                                    onChange={handleInputChange('sql_enabled')}
                                    disabled={loading}
                                />
                            }
                            label="SQL Injection Protection"
                        />
                        <FormControlLabel
                            control={
                                <Switch
                                    checked={formData.vt_enabled}
                                    onChange={handleInputChange('vt_enabled')}
                                    disabled={loading}
                                />
                            }
                            label="VirusTotal IP Check"
                        />
                    </Box>
                </Box>
            </DialogContent>
            <DialogActions>
                <Button onClick={handleClose} disabled={loading}>
                    Cancel
                </Button>
                <Button
                    onClick={handleSubmit}
                    variant="contained"
                    disabled={loading}
                    startIcon={loading ? <CircularProgress size={16} /> : undefined}
                >
                    {loading ? 'Updating...' : 'Update'}
                </Button>
            </DialogActions>
        </Dialog>
    );
};

export default EditSiteModal;
