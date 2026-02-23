import { useState } from 'react';
import {
    Box,
    TextField,
    Button,
    FormControlLabel,
    Switch,
    Paper,
    Typography,
    Alert,
    Stack
} from '@mui/material';
import type { SiteCreate } from '../types/Site';
import { addSite } from '../api/sites';

interface SiteFormProps {
    onSiteAdded: () => void;
}

export function SiteForm({ onSiteAdded }: SiteFormProps) {
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
    const [error, setError] = useState<string>('');

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
                body_inspection_profile: 'default',
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
        setFormData(prev => ({
            ...prev,
            [name]: value
        }));
    };

    const handleSwitchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { name, checked } = e.target;
        setFormData(prev => ({
            ...prev,
            [name]: checked
        }));
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

                    <TextField
                        required
                        fullWidth
                        label="Body Inspection Profile"
                        name="body_inspection_profile"
                        value={formData.body_inspection_profile}
                        onChange={handleChange}
                        placeholder="default"
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
                    </Box>

                    <Box sx={{ display: 'flex', gap: 2 }}>
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
