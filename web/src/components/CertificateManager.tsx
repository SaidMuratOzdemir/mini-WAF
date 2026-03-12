import { useEffect, useRef, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
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
  Upload,
  Star,
  Trash2,
  ShieldCheck,
  FileKey,
  FileText,
  Link2,
} from "lucide-react";
import { toast } from "sonner";

import type { Certificate } from "@/types/Certificate";
import {
  deleteCertificate,
  fetchCertificates,
  setDefaultCertificate,
  uploadCertificate,
} from "@/api/certificates";

interface CertificateManagerProps {
  onCertificatesChanged?: () => void;
}

export default function CertificateManager({
  onCertificatesChanged,
}: CertificateManagerProps) {
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [name, setName] = useState("");
  const [certFile, setCertFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [chainFile, setChainFile] = useState<File | null>(null);
  const [isDefault, setIsDefault] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const certRef = useRef<HTMLInputElement>(null);
  const keyRef = useRef<HTMLInputElement>(null);
  const chainRef = useRef<HTMLInputElement>(null);

  const loadCertificates = async () => {
    try {
      const data = await fetchCertificates();
      setCertificates(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load certificates");
    }
  };

  useEffect(() => {
    void loadCertificates();
  }, []);

  const notifyChange = () => {
    if (onCertificatesChanged) onCertificatesChanged();
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!name.trim()) {
      setError("Certificate name is required");
      return;
    }
    if (!certFile || !keyFile) {
      setError("Certificate and private key files are required");
      return;
    }

    const formData = new FormData();
    formData.append("name", name.trim());
    formData.append("is_default", String(isDefault));
    formData.append("cert_file", certFile);
    formData.append("key_file", keyFile);
    if (chainFile) formData.append("chain_file", chainFile);

    try {
      setLoading(true);
      await uploadCertificate(formData);
      setName("");
      setCertFile(null);
      setKeyFile(null);
      setChainFile(null);
      setIsDefault(false);
      toast.success("Certificate uploaded successfully!");
      await loadCertificates();
      notifyChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Certificate upload failed");
    } finally {
      setLoading(false);
    }
  };

  const handleSetDefault = async (certificateId: number) => {
    try {
      setLoading(true);
      await setDefaultCertificate(certificateId);
      toast.success("Default certificate updated");
      await loadCertificates();
      notifyChange();
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Failed to set default certificate"
      );
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (certificateId: number) => {
    try {
      setLoading(true);
      await deleteCertificate(certificateId);
      toast.success("Certificate deleted");
      await loadCertificates();
      notifyChange();
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Failed to delete certificate"
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="border-zinc-800/70 bg-zinc-900/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg text-zinc-100">
          <ShieldCheck className="h-5 w-5 text-emerald-400" />
          TLS Certificates
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        {error && (
          <Alert
            variant="destructive"
            className="border-red-900/50 bg-red-950/30"
          >
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Upload Form */}
        <form onSubmit={handleUpload} className="space-y-4">
          <div className="space-y-2">
            <Label className="text-zinc-300">Certificate Name *</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={loading}
              placeholder="e.g., wildcard-example-com"
              className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <input
                ref={certRef}
                type="file"
                accept=".pem,.crt,.cer,.txt"
                className="hidden"
                onChange={(e) => setCertFile(e.target.files?.[0] || null)}
              />
              <Button
                type="button"
                variant="outline"
                className="w-full border-zinc-700 bg-zinc-950/50 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 justify-start"
                disabled={loading}
                onClick={() => certRef.current?.click()}
              >
                <FileText className="h-4 w-4 mr-2 shrink-0 text-emerald-400" />
                <span className="truncate">
                  {certFile ? certFile.name : "Certificate PEM *"}
                </span>
              </Button>
            </div>
            <div>
              <input
                ref={keyRef}
                type="file"
                accept=".pem,.key,.txt"
                className="hidden"
                onChange={(e) => setKeyFile(e.target.files?.[0] || null)}
              />
              <Button
                type="button"
                variant="outline"
                className="w-full border-zinc-700 bg-zinc-950/50 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 justify-start"
                disabled={loading}
                onClick={() => keyRef.current?.click()}
              >
                <FileKey className="h-4 w-4 mr-2 shrink-0 text-amber-400" />
                <span className="truncate">
                  {keyFile ? keyFile.name : "Private Key PEM *"}
                </span>
              </Button>
            </div>
            <div>
              <input
                ref={chainRef}
                type="file"
                accept=".pem,.crt,.cer,.txt"
                className="hidden"
                onChange={(e) => setChainFile(e.target.files?.[0] || null)}
              />
              <Button
                type="button"
                variant="outline"
                className="w-full border-zinc-700 bg-zinc-950/50 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 justify-start"
                disabled={loading}
                onClick={() => chainRef.current?.click()}
              >
                <Link2 className="h-4 w-4 mr-2 shrink-0 text-sky-400" />
                <span className="truncate">
                  {chainFile ? chainFile.name : "Chain PEM (optional)"}
                </span>
              </Button>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <Label className="text-zinc-300 text-sm">
              Set as default certificate
            </Label>
            <Switch
              checked={isDefault}
              onCheckedChange={setIsDefault}
              disabled={loading}
            />
          </div>

          <Button
            type="submit"
            disabled={loading}
            className="w-full bg-emerald-500 text-zinc-950 hover:bg-emerald-400 shadow-[0_0_0_1px_rgba(16,185,129,0.35),0_0_25px_rgba(16,185,129,0.12)]"
          >
            <Upload className="h-4 w-4 mr-2" />
            Upload Certificate
          </Button>
        </form>

        <Separator className="bg-zinc-800/50" />

        {/* Certificates Table */}
        <div>
          <h3 className="text-sm font-semibold text-zinc-300 mb-3">
            Registered Certificates
          </h3>
          <div className="rounded-md border border-zinc-800/70 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800/70 hover:bg-transparent">
                  <TableHead className="text-zinc-400">Name</TableHead>
                  <TableHead className="text-zinc-400">Default</TableHead>
                  <TableHead className="text-zinc-400">Chain</TableHead>
                  <TableHead className="text-zinc-400 text-right">
                    Actions
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {certificates.map((certificate) => (
                  <TableRow
                    key={certificate.id}
                    className="border-zinc-800/70 hover:bg-zinc-800/30"
                  >
                    <TableCell className="text-zinc-200 font-medium">
                      {certificate.name}
                    </TableCell>
                    <TableCell>
                      {certificate.is_default ? (
                        <span className="text-amber-400 text-xs font-medium">
                          ★ Default
                        </span>
                      ) : (
                        <span className="text-zinc-500 text-xs">No</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <span
                        className={
                          certificate.has_chain
                            ? "text-emerald-400 text-xs"
                            : "text-zinc-500 text-xs"
                        }
                      >
                        {certificate.has_chain ? "Yes" : "No"}
                      </span>
                    </TableCell>
                    <TableCell className="text-right space-x-1">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-amber-400 hover:text-amber-300 hover:bg-amber-500/10"
                            disabled={loading || certificate.is_default}
                            onClick={() => handleSetDefault(certificate.id)}
                          >
                            <Star
                              className={`h-4 w-4 ${certificate.is_default ? "fill-amber-400" : ""}`}
                            />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>Set as default</TooltipContent>
                      </Tooltip>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-red-400 hover:text-red-300 hover:bg-red-500/10"
                            disabled={loading}
                            onClick={() => handleDelete(certificate.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>Delete certificate</TooltipContent>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
                {certificates.length === 0 && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell
                      colSpan={4}
                      className="text-center text-zinc-500 py-8"
                    >
                      No certificates uploaded yet.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
