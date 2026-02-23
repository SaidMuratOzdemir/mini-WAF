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
    CircularProgress
} from '@mui/material';
import type { Site, SiteCreate } from '../types/Site';
import { updateSite } from '../api/sites';

interface EditSiteModalProps {
    open: boolean;
    site: Site | null;
    onClose: () => void;
    onSuccess: () => void;
}

const EditSiteModal = ({ open, site, onClose, onSuccess }: EditSiteModalProps) => {
    const [formData, setFormData] = useState<SiteCreate>({
        host: '',
        name: '',
        upstream_url: '',
        is_active: true,
        preserve_host_header: false,
        enable_sni: true,
        websocket_enabled: true,
        body_inspection_profile: 'default',
        xss_enabled: true,
        sql_enabled: true,
        vt_enabled: false
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Reset form when site changes
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
        const value = event.target.type === 'checkbox'
            ? event.target.checked
            : event.target.value;

        setFormData(prev => ({
            ...prev,
            [field]: value
        }));
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
