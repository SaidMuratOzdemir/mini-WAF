import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import { AlertTriangle, Plus, Info } from "lucide-react";
import type { SiteCreate } from "@/types/Site";
import { addSite } from "@/api/sites";
import { fetchCertificates } from "@/api/certificates";
import type { Certificate } from "@/types/Certificate";
import { toast } from "sonner";

interface SiteFormProps {
  onSiteAdded: () => void;
  certRefreshToken?: number;
  currentUserRole?: "admin" | "super_admin" | null;
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

const INITIAL_FORM: SiteCreate = {
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
};

export function SiteForm({
  onSiteAdded,
  certRefreshToken = 0,
  currentUserRole = null,
}: SiteFormProps) {
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [formData, setFormData] = useState<SiteCreate>({ ...INITIAL_FORM });
  const [error, setError] = useState("");
  const upstreamIsHttps = formData.upstream_url
    .trim()
    .toLowerCase()
    .startsWith("https://");

  useEffect(() => {
    if (currentUserRole !== "super_admin") {
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
  }, [certRefreshToken, currentUserRole]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (!formData.name.trim()) throw new Error("Site name is required");
      if (!formData.host.trim()) throw new Error("Host field is required");
      if (!formData.upstream_url.trim())
        throw new Error("Upstream URL is required");
      if (
        formData.proxy_read_timeout_sec < 1 ||
        formData.proxy_send_timeout_sec < 1 ||
        formData.proxy_connect_timeout_sec < 1
      )
        throw new Error("Proxy timeout değerleri 1 saniyeden büyük olmalıdır.");
      if (
        formData.client_max_body_size_mb !== null &&
        (formData.client_max_body_size_mb < 1 ||
          formData.client_max_body_size_mb > 1024)
      )
        throw new Error("Body size 1..1024 MB aralığında olmalıdır.");
      if (
        currentUserRole !== "super_admin" &&
        isLikelyPrivateUpstream(formData.upstream_url)
      )
        throw new Error(
          "Private/LAN upstream tanımı yalnızca super_admin rolü için izinlidir."
        );
      if (
        formData.tls_enabled &&
        !formData.tls_certificate_id &&
        certificates.length === 0
      )
        throw new Error(
          "TLS enabled requires a certificate (upload one or configure a default)."
        );

      await addSite(formData);
      onSiteAdded();
      setFormData({ ...INITIAL_FORM });
      setError("");
      toast.success("Site added successfully!");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to add site");
    }
  };

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
        disabled={disabled}
      />
    </div>
  );

  return (
    <Card className="border-zinc-800/70 bg-zinc-900/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg text-zinc-100">
          <Plus className="h-5 w-5 text-emerald-400" />
          Add New Site
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
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
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="space-y-2">
              <Label className="text-zinc-300">Site Name *</Label>
              <Input
                value={formData.name}
                onChange={(e) => set("name", e.target.value)}
                placeholder="My Application"
                className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Host *</Label>
              <Input
                value={formData.host}
                onChange={(e) => set("host", e.target.value)}
                placeholder="app.example.com"
                className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Upstream URL *</Label>
              <Input
                value={formData.upstream_url}
                onChange={(e) => set("upstream_url", e.target.value)}
                placeholder="http://app-internal:8080"
                className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
              />
            </div>
          </div>

          {currentUserRole !== "super_admin" && (
            <div className="flex items-start gap-2 rounded-lg border border-sky-500/20 bg-sky-500/5 p-3">
              <Info className="h-4 w-4 text-sky-400 mt-0.5 shrink-0" />
              <p className="text-xs text-sky-300">
                Private/LAN upstream hedefleri yalnızca super_admin rolü
                tarafından eklenebilir.
              </p>
            </div>
          )}

          <Separator className="bg-zinc-800/50" />

          {/* Dropdowns row */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="space-y-2">
              <Label className="text-zinc-300">Body Inspection</Label>
              <Select
                value={formData.body_inspection_profile}
                onValueChange={(v) => set("body_inspection_profile", v)}
              >
                <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="border-zinc-800 bg-zinc-900">
                  <SelectItem value="strict">strict</SelectItem>
                  <SelectItem value="default">default</SelectItem>
                  <SelectItem value="headers_only">headers_only</SelectItem>
                  <SelectItem value="upload_friendly">upload_friendly</SelectItem>
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
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
                    !formData.tls_enabled ||
                    currentUserRole !== "super_admin"
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
                  disabled={!upstreamIsHttps}
                  placeholder="upstream.example.com"
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
                />
              </div>
            </div>
          </div>

          <Separator className="bg-zinc-800/50" />

          {/* Switches Grid */}
          <div>
            <h3 className="text-sm font-semibold text-zinc-300 mb-3">
              Features & Protection
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
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

          {/* Proxy Timeouts */}
          <div>
            <h3 className="text-sm font-semibold text-zinc-300 mb-3">
              Proxy Timeouts
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
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
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100"
                />
              </div>
            </div>
          </div>

          <Button
            type="submit"
            className="w-full bg-emerald-500 text-zinc-950 hover:bg-emerald-400 shadow-[0_0_0_1px_rgba(16,185,129,0.35),0_0_25px_rgba(16,185,129,0.12)]"
          >
            <Plus className="h-4 w-4 mr-2" />
            Add Site
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
