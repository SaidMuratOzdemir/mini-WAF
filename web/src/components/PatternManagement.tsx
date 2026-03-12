import React, { useEffect, useState, useMemo } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
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
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Plus,
  Upload,
  Search,
  Pencil,
  Trash2,
  Loader2,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  AlertTriangle,
} from "lucide-react";
import { useForm, Controller } from "react-hook-form";
import { useDropzone } from "react-dropzone";
import debounce from "lodash.debounce";
import { toast } from "sonner";
import {
  Pattern,
  PatternCreate,
  PatternType,
} from "@/types/Pattern";
import {
  getPatterns,
  addPattern,
  addPatternsFromTxt,
  updatePattern,
  deletePattern,
  PatternUploadResult,
} from "@/api/patterns";

const patternTypes = [
  { value: PatternType.XSS, label: "XSS" },
  { value: PatternType.SQL, label: "SQL" },
  { value: PatternType.CUSTOM, label: "CUSTOM" },
];

const extendedPatternTypes: Array<{
  value: string;
  label: string;
  badgeClass: string;
  backendType: PatternType;
}> = [
  {
    value: PatternType.XSS,
    label: "XSS",
    badgeClass: "bg-red-500/15 text-red-400 border-red-500/30",
    backendType: PatternType.XSS,
  },
  {
    value: PatternType.SQL,
    label: "SQL",
    badgeClass: "bg-sky-500/15 text-sky-400 border-sky-500/30",
    backendType: PatternType.SQL,
  },
  {
    value: PatternType.CUSTOM,
    label: "CUSTOM",
    badgeClass: "bg-zinc-700/50 text-zinc-300 border-zinc-600/50",
    backendType: PatternType.CUSTOM,
  },
  {
    value: "RCE",
    label: "RCE",
    badgeClass: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    backendType: PatternType.CUSTOM,
  },
  {
    value: "LFI",
    label: "LFI",
    badgeClass: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    backendType: PatternType.CUSTOM,
  },
  {
    value: "SSRF",
    label: "SSRF",
    badgeClass: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    backendType: PatternType.CUSTOM,
  },
  {
    value: "OpenRedirect",
    label: "Open Redirect",
    badgeClass: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
    backendType: PatternType.CUSTOM,
  },
  {
    value: "PathTraversal",
    label: "Path Traversal",
    badgeClass: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
    backendType: PatternType.CUSTOM,
  },
  {
    value: "XXE",
    label: "XXE",
    badgeClass: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    backendType: PatternType.CUSTOM,
  },
  {
    value: "CSRF",
    label: "CSRF",
    badgeClass: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    backendType: PatternType.CUSTOM,
  },
];

function typeBadge(type: string) {
  const t = extendedPatternTypes.find((x) => x.value === type);
  const cls = t?.badgeClass ?? "bg-zinc-700/50 text-zinc-300 border-zinc-600/50";
  const label = t?.label ?? type;
  return (
    <Badge variant="outline" className={cls + " hover:" + cls.split(" ")[0]}>
      {label}
    </Badge>
  );
}

const defaultFormValues: PatternCreate = {
  pattern: "",
  type: PatternType.CUSTOM,
  description: "",
};

const PatternManagement: React.FC = () => {
  const [patterns, setPatterns] = useState<Pattern[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [filter, setFilter] = useState<string>("");
  const [search, setSearch] = useState("");
  const [searchDebounced, setSearchDebounced] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [openAdd, setOpenAdd] = useState(false);
  const [openEdit, setOpenEdit] = useState(false);
  const [editPatternData, setEditPatternData] = useState<Pattern | null>(null);
  const [openUpload, setOpenUpload] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] =
    useState<PatternUploadResult | null>(null);
  const [txtFile, setTxtFile] = useState<File | null>(null);
  const [openDelete, setOpenDelete] = useState<{
    open: boolean;
    id: number | null;
  }>({ open: false, id: null });
  const [uploadPatternType, setUploadPatternType] = useState<string>(
    PatternType.CUSTOM
  );

  const { control, handleSubmit, reset } = useForm<PatternCreate>({
    defaultValues: defaultFormValues,
  });
  const {
    control: editControl,
    handleSubmit: handleEditSubmit,
    reset: resetEdit,
  } = useForm<PatternCreate>({ defaultValues: defaultFormValues });

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop: (files: File[]) => setTxtFile(files[0]),
    accept: { "text/plain": [".txt"] },
    multiple: false,
  });

  const debouncedSetSearch = useMemo(
    () => debounce((val: string) => setSearchDebounced(val), 400),
    []
  );
  useEffect(() => {
    debouncedSetSearch(search);
  }, [search, debouncedSetSearch]);

  const fetchPatterns = async (
    pageArg = page,
    pageSizeArg = pageSize,
    filterArg = filter,
    searchArg = searchDebounced
  ) => {
    setLoading(true);
    try {
      const enumValues = Object.values(PatternType) as string[];
      const backendFilter =
        filterArg && enumValues.includes(filterArg)
          ? (filterArg as PatternType)
          : undefined;
      const res = await getPatterns(
        pageArg,
        pageSizeArg,
        backendFilter,
        searchArg || undefined
      );
      setPatterns(res.items);
      setTotal(res.total);
      setError(null);
    } catch (e: any) {
      setError(e.message || "Failed to fetch data.");
      setPatterns([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPatterns(1, pageSize, filter, searchDebounced);
    setPage(1);
  }, [filter, pageSize, searchDebounced]);
  useEffect(() => {
    fetchPatterns(page, pageSize, filter, searchDebounced);
  }, [page]);

  const onAdd = async (data: PatternCreate) => {
    try {
      await addPattern({ ...data, type: data.type as PatternType });
      toast.success("Pattern added successfully.");
      setOpenAdd(false);
      reset(defaultFormValues);
      fetchPatterns();
    } catch (e: any) {
      toast.error(e.message || JSON.stringify(e));
    }
  };

  const onEdit = async (data: PatternCreate) => {
    if (!editPatternData) return;
    try {
      await updatePattern(editPatternData.id, {
        ...data,
        type: data.type as PatternType,
      });
      toast.success("Pattern updated.");
      setOpenEdit(false);
      setEditPatternData(null);
      fetchPatterns();
    } catch (e: any) {
      toast.error(e.message || JSON.stringify(e));
    }
  };

  const onDelete = async () => {
    if (!openDelete.id) return;
    try {
      await deletePattern(openDelete.id);
      toast.success("Pattern deleted.");
      setOpenDelete({ open: false, id: null });
      fetchPatterns();
    } catch (e: any) {
      toast.error(e.message || "Failed to delete pattern.");
    }
  };

  const handleTxtUpload = async () => {
    if (!txtFile) return;
    setUploading(true);
    try {
      const backendType =
        extendedPatternTypes.find((t) => t.value === uploadPatternType)
          ?.backendType ?? PatternType.CUSTOM;
      const result = await addPatternsFromTxt(txtFile, backendType);
      setUploadResult(result);
      const typeLabel =
        extendedPatternTypes.find((t) => t.value === uploadPatternType)
          ?.label || uploadPatternType;
      toast[result.failed === 0 ? "success" : "error"](
        `${result.success} ${typeLabel} patterns added, ${result.failed} errors.`
      );
      setTxtFile(null);
      fetchPatterns();
    } catch (e: any) {
      setUploadResult({
        success: 0,
        failed: 0,
        errors: [e.message || "Unknown error"],
      });
      toast.error("Upload failed.");
    } finally {
      setUploading(false);
    }
  };

  const openAddModal = () => {
    setOpenAdd(true);
    reset(defaultFormValues);
  };
  const openEditModal = (pattern: Pattern) => {
    setEditPatternData(pattern);
    setOpenEdit(true);
    resetEdit(pattern);
  };
  const closeModals = () => {
    setOpenAdd(false);
    setOpenEdit(false);
    setEditPatternData(null);
    reset(defaultFormValues);
    resetEdit(defaultFormValues);
  };

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="space-y-6">
      {/* Toolbar */}
      <Card className="border-zinc-800/70 bg-zinc-900/50">
        <CardContent className="pt-6">
          <div className="flex flex-wrap items-end gap-3">
            <Button
              onClick={openAddModal}
              className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
            >
              <Plus className="h-4 w-4 mr-1.5" />
              Add Pattern
            </Button>
            <Button
              variant="outline"
              onClick={() => setOpenUpload(true)}
              className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100"
            >
              <Upload className="h-4 w-4 mr-1.5" />
              Upload Patterns
            </Button>

            <Select value={filter} onValueChange={setFilter}>
              <SelectTrigger className="w-[140px] border-zinc-800 bg-zinc-950/70 text-zinc-200">
                <SelectValue placeholder="All Types" />
              </SelectTrigger>
              <SelectContent className="border-zinc-800 bg-zinc-900">
                <SelectItem value="all">All</SelectItem>
                {extendedPatternTypes.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <div className="relative flex-1 min-w-[180px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search patterns..."
                className="pl-9 border-zinc-800 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500"
              />
            </div>

            <Select
              value={String(pageSize)}
              onValueChange={(v) => setPageSize(Number(v))}
            >
              <SelectTrigger className="w-[110px] border-zinc-800 bg-zinc-950/70 text-zinc-200">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="border-zinc-800 bg-zinc-900">
                {[10, 20, 50, 100].map((s) => (
                  <SelectItem key={s} value={String(s)}>
                    {s}/page
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Table */}
      <div className="rounded-md border border-zinc-800/70 overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="border-zinc-800/70 hover:bg-transparent">
              <TableHead className="text-zinc-400">Pattern</TableHead>
              <TableHead className="text-zinc-400">Type</TableHead>
              <TableHead className="text-zinc-400">Description</TableHead>
              <TableHead className="text-zinc-400 text-right">
                Actions
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={4} className="text-center py-12">
                  <Loader2 className="h-6 w-6 animate-spin text-emerald-400 mx-auto" />
                </TableCell>
              </TableRow>
            ) : patterns.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell
                  colSpan={4}
                  className="text-center text-zinc-500 py-8"
                >
                  No records found.
                </TableCell>
              </TableRow>
            ) : (
              patterns.map((p) => (
                <TableRow
                  key={p.id}
                  className="border-zinc-800/70 hover:bg-zinc-800/30"
                >
                  <TableCell className="font-mono text-sm text-zinc-200 max-w-[300px] truncate">
                    {p.pattern}
                  </TableCell>
                  <TableCell>{typeBadge(p.type)}</TableCell>
                  <TableCell className="text-zinc-400 text-sm max-w-[250px] truncate">
                    {p.description}
                  </TableCell>
                  <TableCell className="text-right space-x-1">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                          onClick={() => openEditModal(p)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Edit</TooltipContent>
                    </Tooltip>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-red-400 hover:text-red-300 hover:bg-red-500/10"
                          onClick={() =>
                            setOpenDelete({ open: true, id: p.id })
                          }
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Delete</TooltipContent>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between">
        <span className="text-sm text-zinc-400">Total: {total}</span>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-zinc-400 hover:text-zinc-200"
            disabled={page <= 1}
            onClick={() => setPage(1)}
          >
            <ChevronsLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-zinc-400 hover:text-zinc-200"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <span className="text-sm text-zinc-300 px-3">
            {page} / {totalPages || 1}
          </span>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-zinc-400 hover:text-zinc-200"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8 text-zinc-400 hover:text-zinc-200"
            disabled={page >= totalPages}
            onClick={() => setPage(totalPages)}
          >
            <ChevronsRight className="h-4 w-4" />
          </Button>
        </div>
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

      {/* Add Pattern Modal */}
      <Dialog open={openAdd} onOpenChange={(v) => !v && closeModals()}>
        <DialogContent className="border-zinc-800 bg-zinc-900 max-w-md">
          <DialogHeader>
            <DialogTitle className="text-zinc-100">
              Add New Pattern
            </DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit(onAdd)} className="space-y-4">
            <div className="space-y-2">
              <Label className="text-zinc-300">Pattern *</Label>
              <Controller
                name="pattern"
                control={control}
                rules={{ required: "Pattern is required" }}
                render={({ field, fieldState }) => (
                  <>
                    <Input
                      {...field}
                      className="border-zinc-800 bg-zinc-950/70 text-zinc-100 font-mono"
                    />
                    {fieldState.error && (
                      <p className="text-xs text-red-400">
                        {fieldState.error.message}
                      </p>
                    )}
                  </>
                )}
              />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Type</Label>
              <Controller
                name="type"
                control={control}
                render={({ field }) => (
                  <Select
                    value={field.value}
                    onValueChange={field.onChange}
                  >
                    <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="border-zinc-800 bg-zinc-900">
                      {patternTypes.map((t) => (
                        <SelectItem key={t.value} value={t.value}>
                          {t.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Description</Label>
              <Controller
                name="description"
                control={control}
                render={({ field }) => (
                  <Input
                    {...field}
                    className="border-zinc-800 bg-zinc-950/70 text-zinc-100"
                  />
                )}
              />
            </div>
            <DialogFooter className="gap-2 sm:gap-0">
              <Button
                type="button"
                variant="ghost"
                onClick={closeModals}
                className="text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
              >
                Add
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Edit Pattern Modal */}
      <Dialog open={openEdit} onOpenChange={(v) => !v && closeModals()}>
        <DialogContent className="border-zinc-800 bg-zinc-900 max-w-md">
          <DialogHeader>
            <DialogTitle className="text-zinc-100">Edit Pattern</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleEditSubmit(onEdit)} className="space-y-4">
            <div className="space-y-2">
              <Label className="text-zinc-300">Pattern *</Label>
              <Controller
                name="pattern"
                control={editControl}
                rules={{ required: "Pattern is required" }}
                render={({ field, fieldState }) => (
                  <>
                    <Input
                      {...field}
                      className="border-zinc-800 bg-zinc-950/70 text-zinc-100 font-mono"
                    />
                    {fieldState.error && (
                      <p className="text-xs text-red-400">
                        {fieldState.error.message}
                      </p>
                    )}
                  </>
                )}
              />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Type</Label>
              <Controller
                name="type"
                control={editControl}
                render={({ field }) => (
                  <Select
                    value={field.value}
                    onValueChange={field.onChange}
                  >
                    <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="border-zinc-800 bg-zinc-900">
                      {patternTypes.map((t) => (
                        <SelectItem key={t.value} value={t.value}>
                          {t.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              />
            </div>
            <div className="space-y-2">
              <Label className="text-zinc-300">Description</Label>
              <Controller
                name="description"
                control={editControl}
                render={({ field }) => (
                  <Input
                    {...field}
                    className="border-zinc-800 bg-zinc-950/70 text-zinc-100"
                  />
                )}
              />
            </div>
            <DialogFooter className="gap-2 sm:gap-0">
              <Button
                type="button"
                variant="ghost"
                onClick={closeModals}
                className="text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
              >
                Cancel
              </Button>
              <Button
                type="submit"
                className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
              >
                Save
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Upload Modal */}
      <Dialog
        open={openUpload}
        onOpenChange={(v) => {
          if (!v) {
            setOpenUpload(false);
            setTxtFile(null);
            setUploadPatternType(PatternType.CUSTOM);
            setUploadResult(null);
          }
        }}
      >
        <DialogContent className="border-zinc-800 bg-zinc-900 max-w-md">
          <DialogHeader>
            <DialogTitle className="text-zinc-100">
              Upload Pattern File
            </DialogTitle>
          </DialogHeader>

          <div
            {...getRootProps()}
            className={`rounded-lg border-2 border-dashed p-6 text-center cursor-pointer transition-colors ${
              isDragActive
                ? "border-emerald-400/50 bg-emerald-500/5"
                : "border-zinc-700 bg-zinc-950/50 hover:border-zinc-600"
            }`}
          >
            <input {...getInputProps()} />
            <Upload className="h-8 w-8 text-zinc-500 mx-auto mb-2" />
            <p className="text-sm text-zinc-300">
              {isDragActive
                ? "Drop here"
                : "Drag & drop your file here, or click to select"}
            </p>
            <p className="text-xs text-zinc-500 mt-1">
              Only .txt files. Each line: pattern, comma, type and optional
              description.
            </p>
          </div>

          {txtFile && (
            <p className="text-sm text-zinc-300">
              Selected: <span className="text-emerald-400">{txtFile.name}</span>
            </p>
          )}

          <div className="space-y-2">
            <Label className="text-zinc-300 text-sm">Pattern Type</Label>
            <Select
              value={uploadPatternType}
              onValueChange={setUploadPatternType}
            >
              <SelectTrigger className="border-zinc-800 bg-zinc-950/70 text-zinc-200">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="border-zinc-800 bg-zinc-900">
                {extendedPatternTypes.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {uploading && (
            <div className="flex items-center gap-2 text-sm text-zinc-400">
              <Loader2 className="h-4 w-4 animate-spin" />
              Uploading...
            </div>
          )}

          {uploadResult && (
            <Alert
              className={
                uploadResult.failed === 0
                  ? "border-emerald-500/30 bg-emerald-500/5"
                  : "border-amber-500/30 bg-amber-500/5"
              }
            >
              <AlertDescription className="text-zinc-300 text-sm">
                {uploadResult.success} patterns added, {uploadResult.failed}{" "}
                errors.
                {uploadResult.errors.length > 0 && (
                  <ul className="list-disc pl-4 mt-1 text-red-400 text-xs">
                    {uploadResult.errors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                )}
              </AlertDescription>
            </Alert>
          )}

          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                setOpenUpload(false);
                setTxtFile(null);
                setUploadPatternType(PatternType.CUSTOM);
                setUploadResult(null);
              }}
              className="text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
            >
              Close
            </Button>
            <Button
              onClick={handleTxtUpload}
              disabled={!txtFile || uploading}
              className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
            >
              Upload
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog
        open={openDelete.open}
        onOpenChange={(v) =>
          !v && setOpenDelete({ open: false, id: null })
        }
      >
        <DialogContent className="border-zinc-800 bg-zinc-900 max-w-sm">
          <DialogHeader>
            <DialogTitle className="text-zinc-100">
              Delete Pattern
            </DialogTitle>
          </DialogHeader>
          <p className="text-sm text-zinc-300">
            Are you sure you want to delete this pattern?
          </p>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              variant="ghost"
              onClick={() => setOpenDelete({ open: false, id: null })}
              className="text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
            >
              Cancel
            </Button>
            <Button
              onClick={onDelete}
              className="bg-red-500 text-white hover:bg-red-400"
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default PatternManagement;
