import { useRef, useCallback, useState } from "react";
import { SiteList, SiteListRef } from "./SiteList";
import { SiteForm } from "./SiteForm";
import VirusTotalStats from "./VirusTotalStats";
import CertificateManager from "./CertificateManager";
import { useAuth } from "@/context/AuthContext";

export default function SitesPage() {
  const siteListRef = useRef<SiteListRef>(null);
  const [certRefreshToken, setCertRefreshToken] = useState(0);
  const { role } = useAuth();

  const handleSiteAdded = useCallback(() => {
    siteListRef.current?.refresh();
  }, []);

  const handleCertificatesChanged = useCallback(() => {
    setCertRefreshToken((prev) => prev + 1);
  }, []);

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
          Protected Sites
        </h1>
        <p className="text-sm text-zinc-400">
          Manage your reverse proxy sites and WAF protection rules
        </p>
      </div>

      <VirusTotalStats />

      {role === "super_admin" && (
        <CertificateManager onCertificatesChanged={handleCertificatesChanged} />
      )}

      <SiteForm
        onSiteAdded={handleSiteAdded}
        certRefreshToken={certRefreshToken}
        currentUserRole={role}
      />

      <SiteList ref={siteListRef} />
    </div>
  );
}
