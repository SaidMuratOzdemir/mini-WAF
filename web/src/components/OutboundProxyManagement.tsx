import { useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  AlertTriangle,
  Info,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Rocket,
  Shield,
  Trash2,
  UserPlus,
  Users,
} from "lucide-react";
import { toast } from "sonner";
import {
  applyOutboundProxyConfig,
  createOutboundProfile,
  createOutboundProxyUser,
  createOutboundRule,
  deleteOutboundProfile,
  deleteOutboundProxyUser,
  deleteOutboundRule,
  fetchForwardProxyStatus,
  fetchOutboundProfiles,
  fetchOutboundProxyUsers,
  fetchOutboundRules,
  updateOutboundProfile,
  updateOutboundProxyUser,
  updateOutboundRule,
} from "@/api/forwardProxy";
import { useAuth } from "@/context/AuthContext";
import type {
  ForwardProxyStatus,
  OutboundDestinationRule,
  OutboundDestinationRuleCreate,
  OutboundProxyProfile,
  OutboundProxyProfileCreate,
  OutboundProxyUser,
  OutboundProxyUserCreate,
} from "@/types/OutboundProxy";

const DEFAULT_PROFILE_FORM: OutboundProxyProfileCreate = {
  name: "",
  listen_port: 3128,
  is_enabled: false,
  require_auth: false,
  auth_realm: "WAF Forward Proxy",
  allow_connect_ports: "443,563",
  allowed_client_cidrs: null,
  default_action: "deny",
  block_private_destinations: true,
};

const DEFAULT_RULE_FORM: OutboundDestinationRuleCreate = {
  action: "allow",
  rule_type: "domain_suffix",
  value: "",
  priority: 100,
  is_enabled: true,
};

const OutboundProxyManagement = () => {
  const { role } = useAuth();

  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [profiles, setProfiles] = useState<OutboundProxyProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<number | null>(
    null
  );
  const [rules, setRules] = useState<OutboundDestinationRule[]>([]);
  const [status, setStatus] = useState<ForwardProxyStatus | null>(null);

  const [editingProfileId, setEditingProfileId] = useState<number | null>(null);
  const [profileForm, setProfileForm] =
    useState<OutboundProxyProfileCreate>(DEFAULT_PROFILE_FORM);

  const [editingRuleId, setEditingRuleId] = useState<number | null>(null);
  const [ruleForm, setRuleForm] =
    useState<OutboundDestinationRuleCreate>(DEFAULT_RULE_FORM);

  const [proxyUsers, setProxyUsers] = useState<OutboundProxyUser[]>([]);
  const [userForm, setUserForm] = useState<OutboundProxyUserCreate>({
    username: "",
    password: "",
  });
  const [addingUser, setAddingUser] = useState(false);

  const selectedProfile = useMemo(
    () => profiles.find((p) => p.id === selectedProfileId) ?? null,
    [profiles, selectedProfileId]
  );

  const loadProfiles = async () => {
    const data = await fetchOutboundProfiles();
    setProfiles(data);
    if (data.length === 0) {
      setSelectedProfileId(null);
      return;
    }
    setSelectedProfileId((prev) => {
      if (prev && data.some((p) => p.id === prev)) return prev;
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

  const loadProxyUsers = async () => {
    try {
      const data = await fetchOutboundProxyUsers();
      setProxyUsers(data);
    } catch {
      setProxyUsers([]);
    }
  };

  const refreshAll = async () => {
    setLoading(true);
    setError(null);
    try {
      await loadProfiles();
      await loadStatus();
      await loadProxyUsers();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to load outbound proxy state."
      );
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
        setError(
          err instanceof Error ? err.message : "Failed to load rules."
        );
      }
    };
    void run();
  }, [selectedProfileId]);

  const handleProfileSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!profileForm.name.trim()) {
      setError("Profile name is required.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const payload: OutboundProxyProfileCreate = {
        ...profileForm,
        name: profileForm.name.trim(),
        allowed_client_cidrs:
          profileForm.allowed_client_cidrs?.trim() || null,
      };
      if (editingProfileId) {
        await updateOutboundProfile(editingProfileId, payload);
        toast.success("Profile updated.");
      } else {
        await createOutboundProfile(payload);
        toast.success("Profile created.");
      }
      setEditingProfileId(null);
      setProfileForm(DEFAULT_PROFILE_FORM);
      await refreshAll();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to save profile."
      );
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
      auth_realm: profile.auth_realm ?? "WAF Forward Proxy",
      allow_connect_ports: profile.allow_connect_ports,
      allowed_client_cidrs: profile.allowed_client_cidrs,
      default_action: profile.default_action,
      block_private_destinations: profile.block_private_destinations ?? true,
    });
  };

  const handleProfileDelete = async (profileId: number) => {
    setSaving(true);
    setError(null);
    try {
      await deleteOutboundProfile(profileId);
      if (selectedProfileId === profileId) setSelectedProfileId(null);
      toast.success("Profile deleted.");
      await refreshAll();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to delete profile."
      );
    } finally {
      setSaving(false);
    }
  };

  const handleRuleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!selectedProfileId) {
      setError("Select a profile before adding rules.");
      return;
    }
    if (!ruleForm.value.trim()) {
      setError("Rule value is required.");
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
        toast.success("Rule updated.");
      } else {
        await createOutboundRule(selectedProfileId, payload);
        toast.success("Rule added.");
      }
      setEditingRuleId(null);
      setRuleForm(DEFAULT_RULE_FORM);
      await loadRules(selectedProfileId);
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save rule.");
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
      toast.success("Rule deleted.");
      await loadRules(selectedProfileId);
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete rule.");
    } finally {
      setSaving(false);
    }
  };

  const handleApply = async () => {
    setSaving(true);
    setError(null);
    try {
      await applyOutboundProxyConfig();
      toast.success("Config applied.");
      await loadStatus();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Failed to apply forward proxy config."
      );
    } finally {
      setSaving(false);
    }
  };

  const handleAddProxyUser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userForm.username.trim() || !userForm.password) {
      setError("Username and password are required.");
      return;
    }
    setAddingUser(true);
    setError(null);
    try {
      await createOutboundProxyUser(userForm);
      setUserForm({ username: "", password: "" });
      toast.success("Proxy user created.");
      await loadProxyUsers();
      await loadStatus();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to create proxy user."
      );
    } finally {
      setAddingUser(false);
    }
  };

  const handleToggleProxyUser = async (userId: number, isActive: boolean) => {
    setSaving(true);
    setError(null);
    try {
      await updateOutboundProxyUser(userId, { is_active: !isActive });
      toast.success(isActive ? "User deactivated." : "User activated.");
      await loadProxyUsers();
      await loadStatus();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to update proxy user."
      );
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteProxyUser = async (userId: number) => {
    setSaving(true);
    setError(null);
    try {
      await deleteOutboundProxyUser(userId);
      toast.success("Proxy user deleted.");
      await loadProxyUsers();
      await loadStatus();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to delete proxy user."
      );
    } finally {
      setSaving(false);
    }
  };

  const switchRow = (
    label: string,
    checked: boolean,
    onChange: (v: boolean) => void,
    disabled = false
  ) => (
    <div className="flex items-center justify-between">
      <Label className="text-zinc-300 text-sm">{label}</Label>
      <Switch
        checked={checked}
        onCheckedChange={onChange}
        disabled={disabled}
      />
    </div>
  );

  if (role !== "super_admin") {
    return (
      <div className="p-6">
        <Alert className="border-amber-500/30 bg-amber-500/5">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          <AlertDescription className="text-amber-300">
            Outbound Proxy management is restricted to super_admin role.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Info Banner */}
      <div className="flex items-start gap-2 rounded-lg border border-sky-500/20 bg-sky-500/5 p-3">
        <Info className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" />
        <p className="text-xs text-sky-300">
          Browser/system proxy ayarı için VM_IP:3128 kullanın. HTTPS trafiği
          CONNECT tüneli ile geçer; Phase 9A kapsamında TLS payload inspection
          yoktur.
        </p>
      </div>

      {error && (
        <Alert
          variant="destructive"
          className="border-red-900/50 bg-red-950/30"
        >
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Status */}
      <Card className="border-zinc-800/70 bg-zinc-900/50">
        <CardContent className="pt-6">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <h3 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
                <Rocket className="h-4 w-4 text-emerald-400" />
                Forward Proxy Runtime
              </h3>
              <div className="grid grid-cols-2 gap-x-8 gap-y-0.5 text-xs">
                <span className="text-zinc-400">Active profile:</span>
                <span className="text-zinc-200">
                  {status?.active_profile_name ?? "none"}
                </span>
                <span className="text-zinc-400">Rule count:</span>
                <span className="text-zinc-200">
                  {status?.active_rule_count ?? 0}
                </span>
                <span className="text-zinc-400">Auth:</span>
                <span>
                  {status?.require_auth ? (
                    <Badge className="bg-sky-500/15 text-sky-400 border-sky-500/30 hover:bg-sky-500/15">
                      Basic Auth ({status?.active_auth_user_count ?? 0} users)
                    </Badge>
                  ) : (
                    <Badge
                      variant="outline"
                      className="text-zinc-500 border-zinc-700"
                    >
                      Disabled
                    </Badge>
                  )}
                </span>
                <span className="text-zinc-400">Config path:</span>
                <span className="text-zinc-200 font-mono text-[11px]">
                  {status?.config_path ?? "-"}
                </span>
                <span className="text-zinc-400">Validate:</span>
                <span
                  className={
                    status?.validation?.ok
                      ? "text-emerald-400"
                      : "text-red-400"
                  }
                >
                  {status?.validation?.ok ? "ok" : "failed"}
                </span>
              </div>
            </div>
            <div className="flex gap-2 shrink-0">
              <Button
                variant="outline"
                size="sm"
                onClick={() => void refreshAll()}
                disabled={loading || saving}
                className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100"
              >
                <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
                Refresh
              </Button>
              <Button
                size="sm"
                onClick={() => void handleApply()}
                disabled={loading || saving}
                className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
              >
                {saving ? (
                  <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                ) : (
                  <Rocket className="h-3.5 w-3.5 mr-1.5" />
                )}
                Apply Config
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Profile Form */}
      <Card className="border-zinc-800/70 bg-zinc-900/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg text-zinc-100">
            <Shield className="h-5 w-5 text-emerald-400" />
            {editingProfileId
              ? `Edit Profile #${editingProfileId}`
              : "Create Profile"}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleProfileSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label className="text-zinc-300">Profile Name *</Label>
              <Input
                value={profileForm.name}
                onChange={(e) =>
                  setProfileForm((p) => ({ ...p, name: e.target.value }))
                }
                className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
                placeholder="default-outbound"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label className="text-zinc-300">Listen Port *</Label>
                <Input
                  type="number"
                  value={profileForm.listen_port}
                  onChange={(e) =>
                    setProfileForm((p) => ({
                      ...p,
                      listen_port: Number(e.target.value),
                    }))
                  }
                  min={1}
                  max={65535}
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-zinc-300">CONNECT Ports (CSV)</Label>
                <Input
                  value={profileForm.allow_connect_ports}
                  onChange={(e) =>
                    setProfileForm((p) => ({
                      ...p,
                      allow_connect_ports: e.target.value,
                    }))
                  }
                  placeholder="443,563"
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-zinc-300">Default Action</Label>
                <Select
                  value={profileForm.default_action}
                  onValueChange={(v) =>
                    setProfileForm((p) => ({
                      ...p,
                      default_action: v as "allow" | "deny",
                    }))
                  }
                >
                  <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="border-zinc-800 bg-zinc-900">
                    <SelectItem value="deny">deny</SelectItem>
                    <SelectItem value="allow">allow</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label className="text-zinc-300">
                Allowed Client CIDRs (CSV, optional)
              </Label>
              <Input
                value={profileForm.allowed_client_cidrs ?? ""}
                onChange={(e) =>
                  setProfileForm((p) => ({
                    ...p,
                    allowed_client_cidrs: e.target.value || null,
                  }))
                }
                placeholder="10.0.0.0/24,192.168.1.0/24"
                className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {switchRow("Enabled", profileForm.is_enabled, (v) =>
                setProfileForm((p) => ({ ...p, is_enabled: v }))
              )}
              {switchRow("Require Basic Auth", profileForm.require_auth, (v) =>
                setProfileForm((p) => ({ ...p, require_auth: v }))
              )}
              {switchRow(
                "Block Private Destinations",
                profileForm.block_private_destinations ?? true,
                (v) =>
                  setProfileForm((p) => ({
                    ...p,
                    block_private_destinations: v,
                  }))
              )}
            </div>

            {profileForm.require_auth && (
              <div className="space-y-2">
                <Label className="text-zinc-300">Auth Realm</Label>
                <Input
                  value={profileForm.auth_realm}
                  onChange={(e) =>
                    setProfileForm((p) => ({
                      ...p,
                      auth_realm: e.target.value,
                    }))
                  }
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100"
                />
                <p className="text-xs text-zinc-500">
                  Displayed to proxy clients in the authentication prompt
                </p>
              </div>
            )}

            {profileForm.require_auth &&
              proxyUsers.filter((u) => u.is_active).length === 0 && (
                <Alert className="border-amber-500/30 bg-amber-500/5">
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                  <AlertDescription className="text-amber-300">
                    No active proxy users. You must add at least one user before
                    enabling auth.
                  </AlertDescription>
                </Alert>
              )}

            <div className="flex gap-2">
              <Button
                type="submit"
                disabled={saving || loading}
                className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
              >
                {saving && (
                  <Loader2 className="h-4 w-4 mr-1.5 animate-spin" />
                )}
                {editingProfileId ? "Update Profile" : "Create Profile"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setEditingProfileId(null);
                  setProfileForm(DEFAULT_PROFILE_FORM);
                }}
                disabled={saving || loading}
                className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100"
              >
                Reset
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {/* Profiles Table */}
      <Card className="border-zinc-800/70 bg-zinc-900/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-zinc-100 text-base">Profiles</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-zinc-800/70 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800/70 hover:bg-transparent">
                  <TableHead className="text-zinc-400">ID</TableHead>
                  <TableHead className="text-zinc-400">Name</TableHead>
                  <TableHead className="text-zinc-400">Port</TableHead>
                  <TableHead className="text-zinc-400">Enabled</TableHead>
                  <TableHead className="text-zinc-400">Default</TableHead>
                  <TableHead className="text-zinc-400 text-right">
                    Actions
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {profiles.length === 0 && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell
                      colSpan={6}
                      className="text-center text-zinc-500 py-8"
                    >
                      No profiles yet.
                    </TableCell>
                  </TableRow>
                )}
                {profiles.map((profile) => (
                  <TableRow
                    key={profile.id}
                    className={`border-zinc-800/70 hover:bg-zinc-800/30 ${profile.id === selectedProfileId ? "bg-emerald-500/5" : ""}`}
                  >
                    <TableCell className="text-zinc-400 text-xs">
                      {profile.id}
                    </TableCell>
                    <TableCell className="text-zinc-200 font-medium">
                      {profile.name}
                    </TableCell>
                    <TableCell className="text-zinc-300 font-mono text-sm">
                      {profile.listen_port}
                    </TableCell>
                    <TableCell>
                      {profile.is_enabled ? (
                        <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/15">
                          yes
                        </Badge>
                      ) : (
                        <span className="text-zinc-500 text-xs">no</span>
                      )}
                    </TableCell>
                    <TableCell className="text-zinc-300 text-sm">
                      {profile.default_action}
                    </TableCell>
                    <TableCell className="text-right space-x-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        className={`text-xs ${profile.id === selectedProfileId ? "text-emerald-400" : "text-zinc-400 hover:text-zinc-200"} hover:bg-zinc-800`}
                        onClick={() => setSelectedProfileId(profile.id)}
                      >
                        Select
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                        onClick={() => handleProfileEdit(profile)}
                      >
                        <Pencil className="h-3 w-3 mr-1" />
                        Edit
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10"
                        onClick={() => void handleProfileDelete(profile.id)}
                      >
                        <Trash2 className="h-3 w-3 mr-1" />
                        Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Separator className="bg-zinc-800/50" />

      {/* Proxy Auth Users */}
      <Card className="border-zinc-800/70 bg-zinc-900/50">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-zinc-100 text-base">
            <Users className="h-4 w-4 text-sky-400" />
            Proxy Auth Users
          </CardTitle>
          <p className="text-xs text-zinc-500">
            Credentials required for proxy clients when Basic Auth is enabled.
            Passwords stored as bcrypt hashes.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <form
            onSubmit={handleAddProxyUser}
            className="flex flex-wrap items-end gap-3"
          >
            <div className="space-y-1.5">
              <Label className="text-zinc-400 text-xs">Username</Label>
              <Input
                value={userForm.username}
                onChange={(e) =>
                  setUserForm((p) => ({ ...p, username: e.target.value }))
                }
                placeholder="proxyuser1"
                className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500 w-48"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-zinc-400 text-xs">Password</Label>
              <Input
                type="password"
                value={userForm.password}
                onChange={(e) =>
                  setUserForm((p) => ({ ...p, password: e.target.value }))
                }
                placeholder="Min 12 characters"
                className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500 w-48"
              />
            </div>
            <Button
              type="submit"
              size="sm"
              disabled={addingUser || saving || loading}
              className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
            >
              {addingUser ? (
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
              ) : (
                <UserPlus className="h-3.5 w-3.5 mr-1.5" />
              )}
              Add User
            </Button>
          </form>

          <div className="rounded-md border border-zinc-800/70 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800/70 hover:bg-transparent">
                  <TableHead className="text-zinc-400">ID</TableHead>
                  <TableHead className="text-zinc-400">Username</TableHead>
                  <TableHead className="text-zinc-400">Active</TableHead>
                  <TableHead className="text-zinc-400">Created</TableHead>
                  <TableHead className="text-zinc-400 text-right">
                    Actions
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {proxyUsers.length === 0 && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell
                      colSpan={5}
                      className="text-center text-zinc-500 py-6"
                    >
                      No proxy users yet.
                    </TableCell>
                  </TableRow>
                )}
                {proxyUsers.map((user) => (
                  <TableRow
                    key={user.id}
                    className="border-zinc-800/70 hover:bg-zinc-800/30"
                  >
                    <TableCell className="text-zinc-400 text-xs">
                      {user.id}
                    </TableCell>
                    <TableCell className="text-zinc-200 font-mono text-sm">
                      {user.username}
                    </TableCell>
                    <TableCell>
                      {user.is_active ? (
                        <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/15">
                          active
                        </Badge>
                      ) : (
                        <Badge
                          variant="outline"
                          className="text-zinc-500 border-zinc-700"
                        >
                          inactive
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="text-zinc-400 text-xs">
                      {new Date(user.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell className="text-right space-x-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                        onClick={() =>
                          void handleToggleProxyUser(user.id, user.is_active)
                        }
                        disabled={saving}
                      >
                        {user.is_active ? "Deactivate" : "Activate"}
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10"
                        onClick={() => void handleDeleteProxyUser(user.id)}
                        disabled={saving}
                      >
                        Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Separator className="bg-zinc-800/50" />

      {/* Rules */}
      <Card className="border-zinc-800/70 bg-zinc-900/50">
        <CardHeader className="pb-3">
          <CardTitle className="text-zinc-100 text-base">
            Rules{" "}
            {selectedProfile && (
              <span className="text-emerald-400 font-normal">
                for {selectedProfile.name}
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {!selectedProfile && (
            <Alert className="border-amber-500/30 bg-amber-500/5">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              <AlertDescription className="text-amber-300">
                Create/select a profile to manage destination rules.
              </AlertDescription>
            </Alert>
          )}

          <form onSubmit={handleRuleSubmit} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label className="text-zinc-300">Action</Label>
                <Select
                  value={ruleForm.action}
                  onValueChange={(v) =>
                    setRuleForm((p) => ({
                      ...p,
                      action: v as "allow" | "deny",
                    }))
                  }
                  disabled={!selectedProfile}
                >
                  <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="border-zinc-800 bg-zinc-900">
                    <SelectItem value="allow">allow</SelectItem>
                    <SelectItem value="deny">deny</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label className="text-zinc-300">Rule Type</Label>
                <Select
                  value={ruleForm.rule_type}
                  onValueChange={(v) =>
                    setRuleForm((p) => ({
                      ...p,
                      rule_type:
                        v as OutboundDestinationRuleCreate["rule_type"],
                    }))
                  }
                  disabled={!selectedProfile}
                >
                  <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="border-zinc-800 bg-zinc-900">
                    <SelectItem value="domain_suffix">domain_suffix</SelectItem>
                    <SelectItem value="domain_exact">domain_exact</SelectItem>
                    <SelectItem value="host_exact">host_exact</SelectItem>
                    <SelectItem value="cidr">cidr</SelectItem>
                    <SelectItem value="port">port</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label className="text-zinc-300">Priority</Label>
                <Input
                  type="number"
                  value={ruleForm.priority}
                  onChange={(e) =>
                    setRuleForm((p) => ({
                      ...p,
                      priority: Number(e.target.value),
                    }))
                  }
                  min={0}
                  max={1000000}
                  disabled={!selectedProfile}
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100"
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label className="text-zinc-300">Value *</Label>
              <Input
                value={ruleForm.value}
                onChange={(e) =>
                  setRuleForm((p) => ({ ...p, value: e.target.value }))
                }
                disabled={!selectedProfile}
                placeholder=".github.com"
                className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
              />
            </div>

            <div className="flex items-center justify-between max-w-xs">
              <Label className="text-zinc-300 text-sm">Enabled</Label>
              <Switch
                checked={ruleForm.is_enabled}
                onCheckedChange={(v) =>
                  setRuleForm((p) => ({ ...p, is_enabled: v }))
                }
                disabled={!selectedProfile}
              />
            </div>

            <div className="flex gap-2">
              <Button
                type="submit"
                disabled={!selectedProfile || saving || loading}
                className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
              >
                <Plus className="h-4 w-4 mr-1.5" />
                {editingRuleId ? "Update Rule" : "Add Rule"}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setEditingRuleId(null);
                  setRuleForm(DEFAULT_RULE_FORM);
                }}
                disabled={saving || loading}
                className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100"
              >
                Reset
              </Button>
            </div>
          </form>

          <div className="rounded-md border border-zinc-800/70 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800/70 hover:bg-transparent">
                  <TableHead className="text-zinc-400">ID</TableHead>
                  <TableHead className="text-zinc-400">Action</TableHead>
                  <TableHead className="text-zinc-400">Type</TableHead>
                  <TableHead className="text-zinc-400">Value</TableHead>
                  <TableHead className="text-zinc-400">Priority</TableHead>
                  <TableHead className="text-zinc-400">Enabled</TableHead>
                  <TableHead className="text-zinc-400 text-right">
                    Actions
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.length === 0 && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell
                      colSpan={7}
                      className="text-center text-zinc-500 py-6"
                    >
                      {selectedProfile
                        ? "No rules for this profile."
                        : "Select a profile first."}
                    </TableCell>
                  </TableRow>
                )}
                {rules.map((rule) => (
                  <TableRow
                    key={rule.id}
                    className="border-zinc-800/70 hover:bg-zinc-800/30"
                  >
                    <TableCell className="text-zinc-400 text-xs">
                      {rule.id}
                    </TableCell>
                    <TableCell>
                      <Badge
                        className={
                          rule.action === "allow"
                            ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/15"
                            : "bg-red-500/15 text-red-400 border-red-500/30 hover:bg-red-500/15"
                        }
                      >
                        {rule.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-zinc-300 text-sm">
                      {rule.rule_type}
                    </TableCell>
                    <TableCell className="text-zinc-200 font-mono text-sm">
                      {rule.value}
                    </TableCell>
                    <TableCell className="text-zinc-300 text-sm">
                      {rule.priority}
                    </TableCell>
                    <TableCell>
                      {rule.is_enabled ? (
                        <span className="text-emerald-400 text-xs">yes</span>
                      ) : (
                        <span className="text-zinc-500 text-xs">no</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right space-x-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                        onClick={() => handleRuleEdit(rule)}
                      >
                        <Pencil className="h-3 w-3 mr-1" />
                        Edit
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10"
                        onClick={() => void handleRuleDelete(rule.id)}
                      >
                        <Trash2 className="h-3 w-3 mr-1" />
                        Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default OutboundProxyManagement;
