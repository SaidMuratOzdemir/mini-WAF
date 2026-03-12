import { useEffect, useState, forwardRef, useImperativeHandle } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Pencil,
  Trash2,
  AlertTriangle,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import type { Site } from "@/types/Site";
import { fetchSites, deleteSite } from "@/api/sites";
import EditSiteModal from "./EditSiteModal";
import { toast } from "sonner";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

type Order = "asc" | "desc";
type OrderBy = "host" | "name" | "vt_enabled";

function descendingComparator<T>(a: T, b: T, orderBy: keyof T) {
  if (b[orderBy] < a[orderBy]) return -1;
  if (b[orderBy] > a[orderBy]) return 1;
  return 0;
}

function getComparator<T>(order: Order, orderBy: keyof T) {
  return order === "desc"
    ? (a: T, b: T) => descendingComparator(a, b, orderBy)
    : (a: T, b: T) => -descendingComparator(a, b, orderBy);
}

export interface SiteListRef {
  refresh: () => void;
}

export const SiteList = forwardRef<SiteListRef>((_props, ref) => {
  const [sites, setSites] = useState<Site[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [siteToDelete, setSiteToDelete] = useState<Site | null>(null);
  const [siteToEdit, setSiteToEdit] = useState<Site | null>(null);
  const [openDialog, setOpenDialog] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [order, setOrder] = useState<Order>("asc");
  const [orderBy, setOrderBy] = useState<OrderBy>("host");
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(5);

  const loadSites = async () => {
    try {
      setLoading(true);
      const data = await fetchSites();
      setSites(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load sites");
    } finally {
      setLoading(false);
    }
  };

  const handleRequestSort = (property: OrderBy) => {
    const isAsc = orderBy === property && order === "asc";
    setOrder(isAsc ? "desc" : "asc");
    setOrderBy(property);
  };

  const handleDelete = async (site: Site) => {
    try {
      await deleteSite(site.id);
      setSites(sites.filter((s) => s.id !== site.id));
      toast.success(`Site "${site.name}" (${site.host}) has been removed.`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to delete site");
    }
    setOpenDialog(false);
  };

  const handleEditSuccess = () => {
    toast.success("Site successfully updated!");
    loadSites();
  };

  useImperativeHandle(ref, () => ({ refresh: loadSites }));

  useEffect(() => {
    loadSites();
  }, []);

  if (error) {
    return (
      <Alert variant="destructive" className="border-red-900/50 bg-red-950/30">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>Error</AlertTitle>
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  const sortedSites = loading
    ? []
    : [...sites].sort(getComparator(order, orderBy));
  const paginatedSites = sortedSites.slice(
    page * rowsPerPage,
    page * rowsPerPage + rowsPerPage
  );
  const totalPages = Math.ceil(sites.length / rowsPerPage);

  const healthColor = (status?: string) => {
    if (status === "healthy") return "bg-emerald-400";
    if (status === "unhealthy") return "bg-red-400";
    if (status) return "bg-amber-400";
    return "bg-zinc-600";
  };

  const healthLabel = (status?: string) => {
    if (status === "healthy") return "Healthy";
    if (status === "unhealthy") return "Down / Not responding";
    if (status) return "Unknown";
    return "No health data";
  };

  return (
    <Card className="border-zinc-800/70 bg-zinc-900/50">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg text-zinc-100">Site List</CardTitle>
          <div className="flex items-center gap-2 text-xs text-zinc-500">
            <span>{sites.length} site(s)</span>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow className="border-zinc-800/70 hover:bg-transparent">
              {[
                { id: "host" as OrderBy, label: "Host", sortable: true },
                { id: "name" as OrderBy, label: "Name", sortable: true },
                { id: "xss" as const, label: "XSS", sortable: false },
                { id: "sql" as const, label: "SQL", sortable: false },
                { id: "vt_enabled" as OrderBy, label: "VT", sortable: true },
                { id: "actions" as const, label: "Actions", sortable: false },
              ].map((col) => (
                <TableHead key={col.id} className="text-zinc-400">
                  {col.sortable ? (
                    <button
                      onClick={() => handleRequestSort(col.id as OrderBy)}
                      className="inline-flex items-center gap-1 hover:text-zinc-200 transition-colors"
                    >
                      {col.label}
                      <ArrowUpDown className="h-3 w-3" />
                    </button>
                  ) : (
                    col.label
                  )}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading
              ? [...Array(rowsPerPage)].map((_, i) => (
                  <TableRow key={i} className="border-zinc-800/50">
                    {[...Array(6)].map((_, j) => (
                      <TableCell key={j}>
                        <Skeleton className="h-4 w-20 bg-zinc-800/50" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              : paginatedSites.length === 0
                ? (
                    <TableRow className="border-zinc-800/50">
                      <TableCell
                        colSpan={6}
                        className="text-center py-8 text-zinc-500"
                      >
                        No protected sites found
                      </TableCell>
                    </TableRow>
                  )
                : paginatedSites.map((site) => (
                    <TableRow
                      key={site.id}
                      className="border-zinc-800/50 hover:bg-zinc-800/30"
                    >
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Tooltip>
                            <TooltipTrigger>
                              <span
                                className={`inline-block h-2.5 w-2.5 rounded-full ${healthColor(site.health_status)}`}
                              />
                            </TooltipTrigger>
                            <TooltipContent>
                              {healthLabel(site.health_status)}
                            </TooltipContent>
                          </Tooltip>
                          <span className="font-mono text-sm text-zinc-200">
                            {site.host}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="text-zinc-300">{site.name}</TableCell>
                      <TableCell>
                        <Badge
                          variant={site.xss_enabled ? "default" : "secondary"}
                          className={
                            site.xss_enabled
                              ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                              : "bg-zinc-800 text-zinc-500 border-zinc-700"
                          }
                        >
                          {site.xss_enabled ? "On" : "Off"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={site.sql_enabled ? "default" : "secondary"}
                          className={
                            site.sql_enabled
                              ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                              : "bg-zinc-800 text-zinc-500 border-zinc-700"
                          }
                        >
                          {site.sql_enabled ? "On" : "Off"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={site.vt_enabled ? "default" : "secondary"}
                          className={
                            site.vt_enabled
                              ? "bg-sky-500/20 text-sky-400 border-sky-500/30"
                              : "bg-zinc-800 text-zinc-500 border-zinc-700"
                          }
                        >
                          {site.vt_enabled ? "On" : "Off"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-zinc-400 hover:text-emerald-400 hover:bg-emerald-500/10"
                            onClick={() => {
                              setSiteToEdit(site);
                              setEditModalOpen(true);
                            }}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-zinc-400 hover:text-red-400 hover:bg-red-500/10"
                            onClick={() => {
                              setSiteToDelete(site);
                              setOpenDialog(true);
                            }}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
          </TableBody>
        </Table>

        {/* Pagination */}
        <div className="flex items-center justify-between mt-4 px-2">
          <div className="flex items-center gap-2">
            <span className="text-xs text-zinc-500">Rows per page</span>
            <Select
              value={String(rowsPerPage)}
              onValueChange={(v) => {
                setRowsPerPage(Number(v));
                setPage(0);
              }}
            >
              <SelectTrigger className="h-8 w-16 border-zinc-800 bg-zinc-900 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="border-zinc-800 bg-zinc-900">
                {[5, 10, 25].map((n) => (
                  <SelectItem key={n} value={String(n)}>
                    {n}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-zinc-500">
              Page {page + 1} of {Math.max(totalPages, 1)}
            </span>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-zinc-400"
              disabled={page === 0}
              onClick={() => setPage(page - 1)}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-zinc-400"
              disabled={page >= totalPages - 1}
              onClick={() => setPage(page + 1)}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Delete Dialog */}
        <Dialog open={openDialog} onOpenChange={setOpenDialog}>
          <DialogContent className="border-zinc-800 bg-zinc-950">
            <DialogHeader>
              <DialogTitle className="text-zinc-100">Delete Site</DialogTitle>
              <DialogDescription className="text-zinc-400">
                Are you sure you want to delete "{siteToDelete?.name}" (
                {siteToDelete?.host})? This action cannot be undone.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button
                variant="ghost"
                onClick={() => setOpenDialog(false)}
                className="text-zinc-400"
              >
                Cancel
              </Button>
              <Button
                variant="destructive"
                onClick={() => siteToDelete && handleDelete(siteToDelete)}
                className="bg-red-600 hover:bg-red-700"
              >
                Delete
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Edit Modal */}
        <EditSiteModal
          open={editModalOpen}
          site={siteToEdit}
          onClose={() => setEditModalOpen(false)}
          onSuccess={handleEditSuccess}
        />
      </CardContent>
    </Card>
  );
});

SiteList.displayName = "SiteList";
