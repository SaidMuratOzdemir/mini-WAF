import { useEffect, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Shield,
  RefreshCw,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  Info,
} from "lucide-react";
import { apiFetch } from "@/api/client";
import { toast } from "sonner";

interface CacheStats {
  date: string;
  total_entries: number;
  malicious_count: number;
  clean_count: number;
  error_count: number;
}

interface CleanupResult {
  message: string;
  cleaned_entries: number;
}

const VirusTotalStats = () => {
  const [stats, setStats] = useState<CacheStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [cleanupLoading, setCleanupLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiFetch<CacheStats>("/system/vt-cache/stats");
      setStats(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  const handleCleanup = async () => {
    setCleanupLoading(true);
    try {
      const result = await apiFetch<CleanupResult>("/system/vt-cache/cleanup", {
        method: "POST",
      });
      toast.success(`${result.cleaned_entries} cache entries cleaned`);
      await fetchStats();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cache cleanup error");
    } finally {
      setCleanupLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <Card className="border-zinc-800/70 bg-zinc-900/50">
        <CardContent className="p-6">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="h-5 w-5 text-emerald-400" />
            <span className="font-semibold text-zinc-100">VirusTotal Cache</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[...Array(4)].map((_, i) => (
              <Skeleton key={i} className="h-20 rounded-lg bg-zinc-800/50" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error && !stats) {
    return (
      <Card className="border-zinc-800/70 bg-zinc-900/50">
        <CardContent className="p-6">
          <Alert variant="destructive" className="border-red-900/50 bg-red-950/30">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription className="flex items-center justify-between">
              <span>{error}</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={fetchStats}
                className="text-red-300 hover:text-red-200"
              >
                <RefreshCw className="h-3 w-3 mr-1" /> Retry
              </Button>
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    );
  }

  if (!stats) return null;

  const maliciousPercentage =
    stats.total_entries > 0
      ? Math.round((stats.malicious_count / stats.total_entries) * 100)
      : 0;

  const cleanPercentage =
    stats.total_entries > 0
      ? Math.round((stats.clean_count / stats.total_entries) * 100)
      : 0;

  const statCards = [
    {
      label: "Total Entries",
      value: stats.total_entries,
      icon: Shield,
      color: "text-sky-400",
      bg: "bg-sky-500/10",
      border: "border-sky-500/20",
    },
    {
      label: "Malicious",
      value: stats.malicious_count,
      badge: `${maliciousPercentage}%`,
      icon: XCircle,
      color: "text-red-400",
      bg: "bg-red-500/10",
      border: "border-red-500/20",
    },
    {
      label: "Clean",
      value: stats.clean_count,
      badge: `${cleanPercentage}%`,
      icon: CheckCircle2,
      color: "text-emerald-400",
      bg: "bg-emerald-500/10",
      border: "border-emerald-500/20",
    },
    {
      label: "Errors",
      value: stats.error_count,
      icon: AlertTriangle,
      color: "text-amber-400",
      bg: "bg-amber-500/10",
      border: "border-amber-500/20",
    },
  ];

  return (
    <Card className="border-zinc-800/70 bg-zinc-900/50">
      <CardContent className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-emerald-400" />
            <span className="font-semibold text-zinc-100">VirusTotal Cache</span>
            <span className="text-xs text-zinc-500">{stats.date}</span>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={fetchStats}
              disabled={loading}
              className="text-zinc-400 hover:text-zinc-200"
            >
              <RefreshCw className={`h-3.5 w-3.5 mr-1 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleCleanup}
              disabled={cleanupLoading}
              className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
            >
              {cleanupLoading ? (
                <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />
              ) : (
                <Trash2 className="h-3.5 w-3.5 mr-1" />
              )}
              Clean
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {statCards.map((card) => (
            <div
              key={card.label}
              className={`rounded-lg border ${card.border} ${card.bg} p-4 text-center`}
            >
              <card.icon className={`h-5 w-5 mx-auto mb-2 ${card.color}`} />
              <div className={`text-2xl font-bold ${card.color}`}>{card.value}</div>
              <div className="text-xs text-zinc-400 mt-1">{card.label}</div>
              {card.badge && (
                <Badge
                  variant="secondary"
                  className={`mt-1.5 text-[10px] ${card.bg} ${card.color} border ${card.border}`}
                >
                  {card.badge}
                </Badge>
              )}
            </div>
          ))}
        </div>

        <div className="mt-4 flex items-start gap-2 rounded-lg border border-zinc-800/50 bg-zinc-900/30 p-3">
          <Info className="h-4 w-4 text-zinc-500 mt-0.5 shrink-0" />
          <p className="text-xs text-zinc-500">
            VirusTotal cache checks IP addresses daily and stores results to avoid repeat lookups.
          </p>
        </div>
      </CardContent>
    </Card>
  );
};

export default VirusTotalStats;
