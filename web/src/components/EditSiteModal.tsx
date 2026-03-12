import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { AlertTriangle, Loader2, Save } from "lucide-react";
import type { Site, SiteCreate } from "@/types/Site";
import { updateSite } from "@/api/sites";
import type { Certificate } from "@/types/Certificate";
import { fetchCertificates } from "@/api/certificates";
import { useAuth } from "@/context/AuthContext";
import { toast } from "sonner";

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
    if (host === "localhost" || host.endsWith(".local")) return true;
    if (/^127\./.test(host)) return true;
    if (host === "::1") return true;
    if (/^10\./.test(host)) return true;
    if (/^192\.168\./.test(host)) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host)) return true;
    return false;
  } catch {
    return false;
  }
}

const EditSiteModal = ({
  open,
  site,
  onClose,
  onSuccess,
}: EditSiteModalProps) => {
  const { role } = useAuth();
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [formData, setFormData] = useState<SiteCreate>({
    host: "",
    name: "",
    upstream_url: "",
    is_active: true,
    preserve_host_header: false,
    enable_sni: true,
    websocket_enabled: true,
    sse_enabled: false,
    body_inspection_profile: "default",
    client_max_body_size_mb: null,
    proxy_request_buffering: null,
    proxy_read_timeout_sec: 60,
    proxy_send_timeout_sec: 60,
    proxy_connect_timeout_sec: 10,
    proxy_redirect_mode: "default",
    cookie_rewrite_enabled: false,
    waf_decision_mode: "fail_close",
    tls_enabled: false,
    http_redirect_to_https: false,
    tls_certificate_id: null,
    upstream_tls_verify: true,
    upstream_tls_server_name_override: null,
    hsts_enabled: false,
    xss_enabled: true,
    sql_enabled: true,
    vt_enabled: false,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (role !== "super_admin") {
      setCertificates([]);
      return;
    }
    const loadCertificates = async () => {
      try {
        const data = await fetchCertificates();
        setCertificates(data);
      } catch (e) {
        console.error("Failed to load certificates", e);
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
        upstream_tls_server_name_override:
          site.upstream_tls_server_name_override,
        hsts_enabled: site.hsts_enabled,
        xss_enabled: site.xss_enabled,
        sql_enabled: site.sql_enabled,
        vt_enabled: site.vt_enabled,
      });
    }
    setError(null);
  }, [site]);

  const set = <K extends keyof SiteCreate>(key: K, value: SiteCreate[K]) => {
    setFormData((prev) => {
      const next = { ...prev, [key]: value };
      if (key === "tls_enabled" && value === false) {
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
      setError("Site name is required.");
      return;
    }
    if (!formData.host.trim()) {
      setError("Host field is required.");
      return;
    }
    if (!formData.upstream_url.trim()) {
      setError("Upstream URL is required.");
      return;
    }
    if (
      formData.proxy_read_timeout_sec < 1 ||
      formData.proxy_send_timeout_sec < 1 ||
      formData.proxy_connect_timeout_sec < 1
    ) {
      setError("Proxy timeout değerleri 1 saniyeden büyük olmalıdır.");
      return;
    }
    if (
      formData.client_max_body_size_mb !== null &&
      (formData.client_max_body_size_mb < 1 ||
        formData.client_max_body_size_mb > 1024)
    ) {
      setError("Body size 1..1024 MB aralığında olmalıdır.");
      return;
    }
    if (
      role !== "super_admin" &&
      isLikelyPrivateUpstream(formData.upstream_url)
    ) {
      setError(
        "Private/LAN upstream tanımı yalnızca super_admin rolü için izinlidir."
      );
      return;
    }
    if (
      formData.tls_enabled &&
      !formData.tls_certificate_id &&
      certificates.length === 0
    ) {
      setError(
        "TLS enabled requires a certificate (upload one or configure a default)."
      );
      return;
    }

    setLoading(true);
    setError(null);

    try {
      await updateSite(site.id, formData);
      toast.success("Site updated successfully!");
      onSuccess();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Update failed");
    } finally {
      setLoading(false);
    }
  };

  const upstreamIsHttps = formData.upstream_url
    .trim()
    .toLowerCase()
    .startsWith("https://");

  const switchRow = (
    label: string,
    key: keyof SiteCreate,
    disabled = false
  ) => (
    <div className="flex items-center justify-between">
      <Label className="text-zinc-300 text-sm">{label}</Label>
      <Switch
        checked={!!formData[key]}
        onCheckedChange={(v) => set(key, v as never)}
        disabled={loading || disabled}
      />
    </div>
  );

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!v && !loading) onClose();
      }}
    >
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto border-zinc-800 bg-zinc-900">
        <DialogHeader>
          <DialogTitle className="text-zinc-100">
            Edit Site: {site?.name}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-5 py-2">
          {error && (
            <Alert
              variant="destructive"
              className="border-red-900/50 bg-red-950/30"
            >
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}

          {/* Basic Info */}
          <div className="grid grid-cols-1 gap-4">
            <div className="space-y-2">
              <Label className="text-zinc-300">Site Name *</Label>
              <Input
                value={formData.name}
                onChange={(e) => set("name", e.target.value)}
                disabled={loading}
                className="border-zinc-800 bg-zinc-950/70 text-zinc-100"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Host *</Label>
              <Input
                value={formData.host}
                onChange={(e) => set("host", e.target.value)}
                disabled={loading}
                placeholder="app.example.com"
                className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Upstream URL *</Label>
              <Input
                value={formData.upstream_url}
                onChange={(e) => set("upstream_url", e.target.value)}
                disabled={loading}
                placeholder="http://app-internal:8080"
                className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
              />
            </div>
          </div>

          <Separator className="bg-zinc-800/50" />

          {/* Selects */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label className="text-zinc-300">Body Inspection</Label>
              <Select
                value={formData.body_inspection_profile}
                onValueChange={(v) => set("body_inspection_profile", v)}
                disabled={loading}
              >
                <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="border-zinc-800 bg-zinc-900">
                  <SelectItem value="strict">strict</SelectItem>
                  <SelectItem value="default">default</SelectItem>
                  <SelectItem value="headers_only">headers_only</SelectItem>
                  <SelectItem value="upload_friendly">
                    upload_friendly
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">WAF Decision Mode</Label>
              <Select
                value={formData.waf_decision_mode}
                onValueChange={(v) =>
                  set("waf_decision_mode", v as "fail_open" | "fail_close")
                }
                disabled={loading}
              >
                <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="border-zinc-800 bg-zinc-900">
                  <SelectItem value="fail_close">fail_close</SelectItem>
                  <SelectItem value="fail_open">fail_open</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Proxy Redirect Mode</Label>
              <Select
                value={formData.proxy_redirect_mode}
                onValueChange={(v) =>
                  set(
                    "proxy_redirect_mode",
                    v as "default" | "off" | "rewrite_to_public_host"
                  )
                }
                disabled={loading}
              >
                <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="border-zinc-800 bg-zinc-900">
                  <SelectItem value="default">default</SelectItem>
                  <SelectItem value="off">off</SelectItem>
                  <SelectItem value="rewrite_to_public_host">
                    rewrite_to_public_host
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Request Buffering</Label>
              <Select
                value={
                  formData.proxy_request_buffering === null
                    ? "default"
                    : formData.proxy_request_buffering
                      ? "on"
                      : "off"
                }
                onValueChange={(v) =>
                  set(
                    "proxy_request_buffering",
                    v === "default" ? null : v === "on"
                  )
                }
                disabled={loading}
              >
                <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="border-zinc-800 bg-zinc-900">
                  <SelectItem value="default">Profile Default</SelectItem>
                  <SelectItem value="on">on</SelectItem>
                  <SelectItem value="off">off</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <Separator className="bg-zinc-800/50" />

          {/* TLS Section */}
          <div>
            <h3 className="text-sm font-semibold text-zinc-300 mb-3">
              TLS / HTTPS
            </h3>
            <div className="grid grid-cols-1 gap-4">
              <div className="space-y-2">
                <Label className="text-zinc-300">TLS Certificate</Label>
                <Select
                  value={
                    formData.tls_certificate_id
                      ? String(formData.tls_certificate_id)
                      : "default"
                  }
                  onValueChange={(v) =>
                    set(
                      "tls_certificate_id",
                      v === "default" ? null : Number(v)
                    )
                  }
                  disabled={
                    loading ||
                    !formData.tls_enabled ||
                    role !== "super_admin"
                  }
                >
                  <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                    <SelectValue placeholder="Use Default Certificate" />
                  </SelectTrigger>
                  <SelectContent className="border-zinc-800 bg-zinc-900">
                    <SelectItem value="default">
                      Use Default Certificate
                    </SelectItem>
                    {certificates.map((cert) => (
                      <SelectItem key={cert.id} value={String(cert.id)}>
                        {cert.name}
                        {cert.is_default ? " (default)" : ""}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label className="text-zinc-300">
                  Upstream TLS SNI Override
                </Label>
                <Input
                  value={formData.upstream_tls_server_name_override ?? ""}
                  onChange={(e) =>
                    set(
                      "upstream_tls_server_name_override",
                      e.target.value || null
                    )
                  }
                  disabled={loading || !upstreamIsHttps}
                  placeholder="upstream.example.com"
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
                />
              </div>
            </div>
          </div>

          <Separator className="bg-zinc-800/50" />

          {/* Switches */}
          <div>
            <h3 className="text-sm font-semibold text-zinc-300 mb-3">
              Features & Protection
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {switchRow("Active", "is_active")}
              {switchRow("Preserve Host Header", "preserve_host_header")}
              {switchRow("Enable SNI", "enable_sni")}
              {switchRow("WebSocket", "websocket_enabled")}
              {switchRow("SSE", "sse_enabled")}
              {switchRow("TLS Enabled", "tls_enabled")}
              {switchRow(
                "HTTP → HTTPS Redirect",
                "http_redirect_to_https",
                !formData.tls_enabled
              )}
              {switchRow(
                "Upstream TLS Verify",
                "upstream_tls_verify",
                !upstreamIsHttps
              )}
              {switchRow("HSTS", "hsts_enabled", !formData.tls_enabled)}
              {switchRow("Cookie Rewrite", "cookie_rewrite_enabled")}
              {switchRow("XSS Protection", "xss_enabled")}
              {switchRow("SQL Injection Protection", "sql_enabled")}
              {switchRow("VirusTotal Scan", "vt_enabled")}
            </div>
          </div>

          <Separator className="bg-zinc-800/50" />

          {/* Timeouts */}
          <div>
            <h3 className="text-sm font-semibold text-zinc-300 mb-3">
              Proxy Timeouts
            </h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label className="text-zinc-400 text-xs">
                  Max Body Size (MB)
                </Label>
                <Input
                  type="number"
                  value={formData.client_max_body_size_mb ?? ""}
                  onChange={(e) =>
                    set(
                      "client_max_body_size_mb",
                      e.target.value ? Number(e.target.value) : null
                    )
                  }
                  min={1}
                  max={1024}
                  disabled={loading}
                  placeholder="Default"
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-zinc-400 text-xs">Read (sec)</Label>
                <Input
                  type="number"
                  value={formData.proxy_read_timeout_sec}
                  onChange={(e) =>
                    set("proxy_read_timeout_sec", Number(e.target.value))
                  }
                  min={1}
                  max={3600}
                  disabled={loading}
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-zinc-400 text-xs">Send (sec)</Label>
                <Input
                  type="number"
                  value={formData.proxy_send_timeout_sec}
                  onChange={(e) =>
                    set("proxy_send_timeout_sec", Number(e.target.value))
                  }
                  min={1}
                  max={3600}
                  disabled={loading}
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-zinc-400 text-xs">Connect (sec)</Label>
                <Input
                  type="number"
                  value={formData.proxy_connect_timeout_sec}
                  onChange={(e) =>
                    set("proxy_connect_timeout_sec", Number(e.target.value))
                  }
                  min={1}
                  max={3600}
                  disabled={loading}
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100"
                />
              </div>
            </div>
          </div>
        </div>

        <DialogFooter className="gap-2 sm:gap-0">
          <Button
            variant="ghost"
            onClick={onClose}
            disabled={loading}
            className="text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
          >
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={loading}
            className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
          >
            {loading ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Save className="h-4 w-4 mr-2" />
            )}
            {loading ? "Updating..." : "Update"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default EditSiteModal;
