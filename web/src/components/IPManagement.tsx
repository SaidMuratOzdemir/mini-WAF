import React, { useEffect, useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Loader2, Ban, ShieldCheck, Search, Plus } from "lucide-react";
import { toast } from "sonner";
import {
  getBannedIPs,
  getCleanIPs,
  banIP,
  unbanIP,
  addCleanIP,
  removeCleanIP,
  IPInfo,
} from "@/api/ips";

const ipRegex =
  /^(25[0-5]|2[0-4]\d|[01]?\d\d?)(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$/;

const IPManagement: React.FC = () => {
  const [bannedIPs, setBannedIPs] = useState<IPInfo[]>([]);
  const [cleanIPs, setCleanIPs] = useState<IPInfo[]>([]);
  const [newIP, setNewIP] = useState("");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);

  const fetchIPs = async () => {
    setLoading(true);
    try {
      const [bans, cleans] = await Promise.all([getBannedIPs(), getCleanIPs()]);
      setBannedIPs(bans);
      setCleanIPs(cleans);
    } catch (err: any) {
      toast.error(err.message || "Failed to load IPs");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIPs();
  }, []);

  const filteredBans = useMemo(
    () => bannedIPs.filter((ip) => ip.ip.includes(search)),
    [bannedIPs, search]
  );
  const filteredCleans = useMemo(
    () => cleanIPs.filter((ip) => ip.ip.includes(search)),
    [cleanIPs, search]
  );

  const handleBan = async (ip: string) => {
    if (!ipRegex.test(ip)) {
      toast.error("Invalid IP address.");
      return;
    }
    setLoading(true);
    try {
      await banIP(ip);
      toast.success(`${ip} successfully banned.`);
      fetchIPs();
      setNewIP("");
    } catch (err: any) {
      toast.error(err.message || "Ban error");
    } finally {
      setLoading(false);
    }
  };

  const handleUnban = async (ip: string) => {
    setLoading(true);
    try {
      await unbanIP(ip);
      toast.success(`${ip} unbanned.`);
      fetchIPs();
    } catch (err: any) {
      toast.error(err.message || "Unban error");
    } finally {
      setLoading(false);
    }
  };

  const handleWhitelistAdd = async (ip: string) => {
    if (!ipRegex.test(ip)) {
      toast.error("Invalid IP address.");
      return;
    }
    setLoading(true);
    try {
      await addCleanIP(ip);
      toast.success(`${ip} added to whitelist.`);
      fetchIPs();
      setNewIP("");
    } catch (err: any) {
      toast.error(err.message || "Whitelist error");
    } finally {
      setLoading(false);
    }
  };

  const handleWhitelistRemove = async (ip: string) => {
    setLoading(true);
    try {
      await removeCleanIP(ip);
      toast.success(`${ip} removed from whitelist.`);
      fetchIPs();
    } catch (err: any) {
      toast.error(err.message || "Remove whitelist error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Action Bar */}
      <Card className="border-zinc-800/70 bg-zinc-900/50">
        <CardContent className="pt-6">
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex-1 min-w-[220px] space-y-1.5">
              <label className="text-xs text-zinc-400">Add IP Address</label>
              <div className="flex gap-2">
                <Input
                  value={newIP}
                  onChange={(e) => setNewIP(e.target.value)}
                  placeholder="e.g. 192.168.0.1"
                  className="border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleBan(newIP);
                  }}
                />
                <Button
                  onClick={() => handleBan(newIP)}
                  disabled={loading || !newIP.trim()}
                  className="bg-red-500/90 text-white hover:bg-red-400 shrink-0"
                >
                  <Ban className="h-4 w-4 mr-1.5" />
                  Ban
                </Button>
                <Button
                  variant="outline"
                  onClick={() => handleWhitelistAdd(newIP)}
                  disabled={loading || !newIP.trim()}
                  className="border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10 hover:text-emerald-300 shrink-0"
                >
                  <Plus className="h-4 w-4 mr-1.5" />
                  Whitelist
                </Button>
              </div>
            </div>
            <div className="flex-1 min-w-[220px] space-y-1.5">
              <label className="text-xs text-zinc-400">Search</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
                <Input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Filter IPs..."
                  className="pl-9 border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
                />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {loading && (
        <div className="flex justify-center py-12">
          <Loader2 className="h-8 w-8 animate-spin text-emerald-400" />
        </div>
      )}

      {/* Two-column cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Banned IPs */}
        <Card className="border-red-500/20 bg-zinc-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-zinc-100">
              <Ban className="h-5 w-5 text-red-400" />
              Banned IPs
              <Badge className="ml-auto bg-red-500/15 text-red-400 border-red-500/30 hover:bg-red-500/15">
                {filteredBans.length}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!loading && filteredBans.length === 0 ? (
              <p className="text-zinc-500 text-sm text-center py-6">
                No matching banned IPs.
              </p>
            ) : (
              <div className="rounded-md border border-zinc-800/70 overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800/70 hover:bg-transparent">
                      <TableHead className="text-zinc-400">
                        IP Address
                      </TableHead>
                      <TableHead className="text-zinc-400">
                        Banned At
                      </TableHead>
                      <TableHead className="text-zinc-400 text-right">
                        Action
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredBans.map((ip) => (
                      <TableRow
                        key={ip.ip}
                        className="border-zinc-800/70 hover:bg-zinc-800/30"
                      >
                        <TableCell className="text-zinc-200 font-mono text-sm">
                          {ip.ip}
                        </TableCell>
                        <TableCell className="text-zinc-400 text-xs">
                          {ip.banned_at
                            ? new Date(ip.banned_at).toLocaleString("en-US", {
                                hour12: false,
                              })
                            : "-"}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                            onClick={() => handleUnban(ip.ip)}
                            disabled={loading}
                          >
                            Unban
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Whitelist IPs */}
        <Card className="border-emerald-500/20 bg-zinc-900/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-zinc-100">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
              Whitelist IPs
              <Badge className="ml-auto bg-emerald-500/15 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/15">
                {filteredCleans.length}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {!loading && filteredCleans.length === 0 ? (
              <p className="text-zinc-500 text-sm text-center py-6">
                No matching whitelist IPs.
              </p>
            ) : (
              <div className="rounded-md border border-zinc-800/70 overflow-hidden">
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800/70 hover:bg-transparent">
                      <TableHead className="text-zinc-400">
                        IP Address
                      </TableHead>
                      <TableHead className="text-zinc-400">Added At</TableHead>
                      <TableHead className="text-zinc-400 text-right">
                        Action
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredCleans.map((ip) => (
                      <TableRow
                        key={ip.ip}
                        className="border-zinc-800/70 hover:bg-zinc-800/30"
                      >
                        <TableCell className="text-zinc-200 font-mono text-sm">
                          {ip.ip}
                        </TableCell>
                        <TableCell className="text-zinc-400 text-xs">
                          {ip.added_at
                            ? new Date(ip.added_at).toLocaleString("en-US", {
                                hour12: false,
                              })
                            : "-"}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-red-400 hover:text-red-300 hover:bg-red-500/10"
                            onClick={() => handleWhitelistRemove(ip.ip)}
                            disabled={loading}
                          >
                            Remove
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default IPManagement;
