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
        body_inspection_profile: 'default',
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
                body_inspection_profile: site.body_inspection_profile,
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
                        label="Body Inspection Profile"
                        value={formData.body_inspection_profile}
                        onChange={handleInputChange('body_inspection_profile')}
                        fullWidth
                        required
                        disabled={loading}
                        placeholder="default"
                    />

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
                        disabled={loading || !formData.tls_enabled}
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
                                    disabled={loading || !formData.tls_enabled}
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

                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
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
