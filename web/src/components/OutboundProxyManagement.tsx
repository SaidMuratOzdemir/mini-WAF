import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Divider,
  FormControlLabel,
  MenuItem,
  Paper,
  Stack,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import {
  applyOutboundProxyConfig,
  createOutboundProfile,
  createOutboundRule,
  deleteOutboundProfile,
  deleteOutboundRule,
  fetchForwardProxyStatus,
  fetchOutboundProfiles,
  fetchOutboundRules,
  updateOutboundProfile,
  updateOutboundRule,
} from '../api/forwardProxy';
import { useAuth } from '../context/AuthContext';
import type {
  ForwardProxyStatus,
  OutboundDestinationRule,
  OutboundDestinationRuleCreate,
  OutboundProxyProfile,
  OutboundProxyProfileCreate,
} from '../types/OutboundProxy';

const DEFAULT_PROFILE_FORM: OutboundProxyProfileCreate = {
  name: '',
  listen_port: 3128,
  is_enabled: false,
  require_auth: false,
  allow_connect_ports: '443,563',
  allowed_client_cidrs: null,
  default_action: 'deny',
};

const DEFAULT_RULE_FORM: OutboundDestinationRuleCreate = {
  action: 'allow',
  rule_type: 'domain_suffix',
  value: '',
  priority: 100,
  is_enabled: true,
};

const OutboundProxyManagement = () => {
  const { role } = useAuth();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [profiles, setProfiles] = useState<OutboundProxyProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<number | null>(null);
  const [rules, setRules] = useState<OutboundDestinationRule[]>([]);
  const [status, setStatus] = useState<ForwardProxyStatus | null>(null);

  const [editingProfileId, setEditingProfileId] = useState<number | null>(null);
  const [profileForm, setProfileForm] = useState<OutboundProxyProfileCreate>(DEFAULT_PROFILE_FORM);

  const [editingRuleId, setEditingRuleId] = useState<number | null>(null);
  const [ruleForm, setRuleForm] = useState<OutboundDestinationRuleCreate>(DEFAULT_RULE_FORM);

  const selectedProfile = useMemo(
    () => profiles.find((profile) => profile.id === selectedProfileId) ?? null,
    [profiles, selectedProfileId],
  );

  const loadProfiles = async () => {
    const data = await fetchOutboundProfiles();
    setProfiles(data);
    if (data.length === 0) {
      setSelectedProfileId(null);
      return;
    }
    setSelectedProfileId((prev) => {
      if (prev && data.some((profile) => profile.id === prev)) {
        return prev;
      }
      return data[0].id;
    });
  };

  const loadRules = async (profileId: number) => {
    const data = await fetchOutboundRules(profileId);
    setRules(data);
  };

  const loadStatus = async () => {
    const data = await fetchForwardProxyStatus();
    setStatus(data);
  };

  const refreshAll = async () => {
    setLoading(true);
    setError(null);
    try {
      await loadProfiles();
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load outbound proxy state.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refreshAll();
  }, []);

  useEffect(() => {
    if (!selectedProfileId) {
      setRules([]);
      return;
    }
    const run = async () => {
      try {
        await loadRules(selectedProfileId);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load rules.');
      }
    };
    void run();
  }, [selectedProfileId]);

  const handleProfileSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!profileForm.name.trim()) {
      setError('Profile name is required.');
      return;
    }

    setSaving(true);
    setError(null);
    try {
      const payload: OutboundProxyProfileCreate = {
        ...profileForm,
        name: profileForm.name.trim(),
        allowed_client_cidrs: profileForm.allowed_client_cidrs?.trim() || null,
      };

      if (editingProfileId) {
        await updateOutboundProfile(editingProfileId, payload);
      } else {
        await createOutboundProfile(payload);
      }

      setEditingProfileId(null);
      setProfileForm(DEFAULT_PROFILE_FORM);
      await refreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save profile.');
    } finally {
      setSaving(false);
    }
  };

  const handleProfileEdit = (profile: OutboundProxyProfile) => {
    setEditingProfileId(profile.id);
    setProfileForm({
      name: profile.name,
      listen_port: profile.listen_port,
      is_enabled: profile.is_enabled,
      require_auth: profile.require_auth,
      allow_connect_ports: profile.allow_connect_ports,
      allowed_client_cidrs: profile.allowed_client_cidrs,
      default_action: profile.default_action,
    });
  };

  const handleProfileDelete = async (profileId: number) => {
    setSaving(true);
    setError(null);
    try {
      await deleteOutboundProfile(profileId);
      if (selectedProfileId === profileId) {
        setSelectedProfileId(null);
      }
      await refreshAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete profile.');
    } finally {
      setSaving(false);
    }
  };

  const handleRuleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selectedProfileId) {
      setError('Select a profile before adding rules.');
      return;
    }
    if (!ruleForm.value.trim()) {
      setError('Rule value is required.');
      return;
    }

    setSaving(true);
    setError(null);
    try {
      const payload: OutboundDestinationRuleCreate = {
        ...ruleForm,
        value: ruleForm.value.trim(),
      };
      if (editingRuleId) {
        await updateOutboundRule(editingRuleId, payload);
      } else {
        await createOutboundRule(selectedProfileId, payload);
      }
      setEditingRuleId(null);
      setRuleForm(DEFAULT_RULE_FORM);
      await loadRules(selectedProfileId);
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save rule.');
    } finally {
      setSaving(false);
    }
  };

  const handleRuleEdit = (rule: OutboundDestinationRule) => {
    setEditingRuleId(rule.id);
    setRuleForm({
      action: rule.action,
      rule_type: rule.rule_type,
      value: rule.value,
      priority: rule.priority,
      is_enabled: rule.is_enabled,
    });
  };

  const handleRuleDelete = async (ruleId: number) => {
    if (!selectedProfileId) return;

    setSaving(true);
    setError(null);
    try {
      await deleteOutboundRule(ruleId);
      await loadRules(selectedProfileId);
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete rule.');
    } finally {
      setSaving(false);
    }
  };

  const handleApply = async () => {
    setSaving(true);
    setError(null);
    try {
      await applyOutboundProxyConfig();
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to apply forward proxy config.');
    } finally {
      setSaving(false);
    }
  };

  if (role !== 'super_admin') {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="warning">
          Outbound Proxy management is restricted to `super_admin` role.
        </Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3, display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Typography variant="h4">Outbound Proxy</Typography>

      <Alert severity="info">
        Browser/system proxy ayarı için `VM_IP:3128` kullanın. HTTPS trafiği CONNECT tüneli ile geçer; Phase 9A kapsamında TLS payload inspection yoktur.
      </Alert>

      {error && <Alert severity="error">{error}</Alert>}

      <Paper sx={{ p: 2 }}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} alignItems="center" justifyContent="space-between">
          <Box>
            <Typography variant="h6">Forward Proxy Runtime</Typography>
            <Typography variant="body2">Active profile: {status?.active_profile_name ?? 'none'}</Typography>
            <Typography variant="body2">Rule count: {status?.active_rule_count ?? 0}</Typography>
            <Typography variant="body2">Config path: {status?.config_path ?? '-'}</Typography>
            <Typography variant="body2">Validate: {status?.validation?.ok ? 'ok' : 'failed'}</Typography>
          </Box>
          <Stack direction="row" spacing={1}>
            <Button variant="outlined" onClick={() => void refreshAll()} disabled={loading || saving}>
              Refresh
            </Button>
            <Button variant="contained" onClick={() => void handleApply()} disabled={loading || saving}>
              {saving ? <CircularProgress size={18} /> : 'Apply Config'}
            </Button>
            <Button variant="text" onClick={() => navigate('/sites')}>
              Back to Sites
            </Button>
          </Stack>
        </Stack>
      </Paper>

      <Paper sx={{ p: 2 }}>
        <Typography variant="h6" sx={{ mb: 2 }}>
          {editingProfileId ? `Edit Profile #${editingProfileId}` : 'Create Profile'}
        </Typography>

        <Box component="form" onSubmit={handleProfileSubmit} sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <TextField
            required
            label="Profile Name"
            value={profileForm.name}
            onChange={(event) => setProfileForm((prev) => ({ ...prev, name: event.target.value }))}
          />

          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            <TextField
              required
              type="number"
              label="Listen Port"
              value={profileForm.listen_port}
              onChange={(event) => setProfileForm((prev) => ({ ...prev, listen_port: Number(event.target.value) }))}
              inputProps={{ min: 1, max: 65535 }}
            />
            <TextField
              required
              label="CONNECT Ports (CSV)"
              value={profileForm.allow_connect_ports}
              onChange={(event) => setProfileForm((prev) => ({ ...prev, allow_connect_ports: event.target.value }))}
              placeholder="443,563"
            />
            <TextField
              select
              label="Default Action"
              value={profileForm.default_action}
              onChange={(event) => setProfileForm((prev) => ({ ...prev, default_action: event.target.value as 'allow' | 'deny' }))}
            >
              <MenuItem value="deny">deny</MenuItem>
              <MenuItem value="allow">allow</MenuItem>
            </TextField>
          </Box>

          <TextField
            label="Allowed Client CIDRs (CSV, optional)"
            value={profileForm.allowed_client_cidrs ?? ''}
            onChange={(event) => setProfileForm((prev) => ({ ...prev, allowed_client_cidrs: event.target.value || null }))}
            placeholder="10.0.0.0/24,192.168.1.0/24"
          />

          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            <FormControlLabel
              control={(
                <Switch
                  checked={profileForm.is_enabled}
                  onChange={(event) => setProfileForm((prev) => ({ ...prev, is_enabled: event.target.checked }))}
                />
              )}
              label="Enabled"
            />
            <FormControlLabel
              control={(
                <Switch
                  checked={profileForm.require_auth}
                  onChange={(event) => setProfileForm((prev) => ({ ...prev, require_auth: event.target.checked }))}
                />
              )}
              label="Require Auth (not supported in 9A)"
            />
          </Box>

          <Stack direction="row" spacing={1}>
            <Button type="submit" variant="contained" disabled={saving || loading}>
              {editingProfileId ? 'Update Profile' : 'Create Profile'}
            </Button>
            <Button
              type="button"
              variant="outlined"
              onClick={() => {
                setEditingProfileId(null);
                setProfileForm(DEFAULT_PROFILE_FORM);
              }}
              disabled={saving || loading}
            >
              Reset
            </Button>
          </Stack>
        </Box>
      </Paper>

      <Paper sx={{ p: 2 }}>
        <Typography variant="h6" sx={{ mb: 2 }}>Profiles</Typography>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>ID</TableCell>
                <TableCell>Name</TableCell>
                <TableCell>Port</TableCell>
                <TableCell>Enabled</TableCell>
                <TableCell>Default</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {profiles.map((profile) => (
                <TableRow key={profile.id} selected={profile.id === selectedProfileId}>
                  <TableCell>{profile.id}</TableCell>
                  <TableCell>{profile.name}</TableCell>
                  <TableCell>{profile.listen_port}</TableCell>
                  <TableCell>{profile.is_enabled ? 'yes' : 'no'}</TableCell>
                  <TableCell>{profile.default_action}</TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={1}>
                      <Button size="small" onClick={() => setSelectedProfileId(profile.id)}>
                        Select
                      </Button>
                      <Button size="small" onClick={() => handleProfileEdit(profile)}>
                        Edit
                      </Button>
                      <Button size="small" color="error" onClick={() => void handleProfileDelete(profile.id)}>
                        Delete
                      </Button>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>

      <Divider />

      <Paper sx={{ p: 2 }}>
        <Typography variant="h6" sx={{ mb: 2 }}>
          Rules {selectedProfile ? `for ${selectedProfile.name}` : ''}
        </Typography>

        {!selectedProfile && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            Create/select a profile to manage destination rules.
          </Alert>
        )}

        <Box component="form" onSubmit={handleRuleSubmit} sx={{ display: 'flex', flexDirection: 'column', gap: 2, mb: 3 }}>
          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            <TextField
              select
              label="Action"
              value={ruleForm.action}
              onChange={(event) => setRuleForm((prev) => ({ ...prev, action: event.target.value as 'allow' | 'deny' }))}
              disabled={!selectedProfile}
            >
              <MenuItem value="allow">allow</MenuItem>
              <MenuItem value="deny">deny</MenuItem>
            </TextField>

            <TextField
              select
              label="Rule Type"
              value={ruleForm.rule_type}
              onChange={(event) => setRuleForm((prev) => ({
                ...prev,
                rule_type: event.target.value as OutboundDestinationRuleCreate['rule_type'],
              }))}
              disabled={!selectedProfile}
            >
              <MenuItem value="domain_suffix">domain_suffix</MenuItem>
              <MenuItem value="domain_exact">domain_exact</MenuItem>
              <MenuItem value="host_exact">host_exact</MenuItem>
              <MenuItem value="cidr">cidr</MenuItem>
              <MenuItem value="port">port</MenuItem>
            </TextField>

            <TextField
              type="number"
              label="Priority"
              value={ruleForm.priority}
              onChange={(event) => setRuleForm((prev) => ({ ...prev, priority: Number(event.target.value) }))}
              inputProps={{ min: 0, max: 1000000 }}
              disabled={!selectedProfile}
            />
          </Box>

          <TextField
            required
            label="Value"
            value={ruleForm.value}
            onChange={(event) => setRuleForm((prev) => ({ ...prev, value: event.target.value }))}
            disabled={!selectedProfile}
            placeholder=".github.com"
          />

          <FormControlLabel
            control={(
              <Switch
                checked={ruleForm.is_enabled}
                onChange={(event) => setRuleForm((prev) => ({ ...prev, is_enabled: event.target.checked }))}
                disabled={!selectedProfile}
              />
            )}
            label="Enabled"
          />

          <Stack direction="row" spacing={1}>
            <Button type="submit" variant="contained" disabled={!selectedProfile || saving || loading}>
              {editingRuleId ? 'Update Rule' : 'Add Rule'}
            </Button>
            <Button
              type="button"
              variant="outlined"
              onClick={() => {
                setEditingRuleId(null);
                setRuleForm(DEFAULT_RULE_FORM);
              }}
              disabled={saving || loading}
            >
              Reset
            </Button>
          </Stack>
        </Box>

        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>ID</TableCell>
                <TableCell>Action</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Value</TableCell>
                <TableCell>Priority</TableCell>
                <TableCell>Enabled</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {rules.map((rule) => (
                <TableRow key={rule.id}>
                  <TableCell>{rule.id}</TableCell>
                  <TableCell>{rule.action}</TableCell>
                  <TableCell>{rule.rule_type}</TableCell>
                  <TableCell>{rule.value}</TableCell>
                  <TableCell>{rule.priority}</TableCell>
                  <TableCell>{rule.is_enabled ? 'yes' : 'no'}</TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={1}>
                      <Button size="small" onClick={() => handleRuleEdit(rule)}>Edit</Button>
                      <Button size="small" color="error" onClick={() => void handleRuleDelete(rule.id)}>Delete</Button>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Paper>
    </Box>
  );
};

export default OutboundProxyManagement;
