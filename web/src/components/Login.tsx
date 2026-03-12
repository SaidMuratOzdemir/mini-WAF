import React, { useEffect, useMemo, useRef, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Eye, EyeOff, Loader2, Shield, AlertTriangle } from "lucide-react";
import { useNavigate } from 'react-router-dom';
import { apiFetch } from '../api/client';
import { useAuth } from '../context/AuthContext';

export function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shake, setShake] = useState(false);
  const navigate = useNavigate();
  const { refreshCurrentUser } = useAuth();

  const ipLabel = useMemo(() => "MuWAF Admin Console · Secure Connection", []);

  const brand = {
    ring: "focus-visible:ring-2 focus-visible:ring-emerald-400/50 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-950",
    primaryBtn:
      "bg-emerald-400 text-zinc-950 hover:bg-emerald-300 shadow-[0_0_0_1px_rgba(16,185,129,0.35),0_0_25px_rgba(16,185,129,0.12)]",
    subtleGlow: "shadow-[0_0_0_1px_rgba(16,185,129,0.18),0_0_40px_rgba(59,130,246,0.08)]",
  };

  function triggerError(msg: string) {
    setError(msg);
    setShake(true);
    window.setTimeout(() => setShake(false), 520);
  }

  async function onSubmitLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!username.trim() || !password.trim()) {
      return triggerError("Kullanıcı adı ve şifre zorunludur.");
    }

    setLoading(true);

    try {
      const formData = new FormData();
      formData.append('username', username);
      formData.append('password', password);

      const data = await apiFetch('/auth/login', {
        method: 'POST',
        body: formData,
      });
      localStorage.setItem('token', data.access_token);
      await refreshCurrentUser();
      navigate('/sites');
    } catch (err) {
      triggerError(err instanceof Error ? err.message : 'Kimlik doğrulama başarısız.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen w-full bg-zinc-950 text-zinc-50">
      <StyleExtras />

      <div className="relative grid min-h-screen grid-cols-1 lg:grid-cols-2">
        {/* LEFT: Brand / Visual */}
        <div className="relative overflow-hidden border-b border-zinc-900/80 lg:border-b-0 lg:border-r lg:border-zinc-900/80">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_15%,rgba(16,185,129,0.18),transparent_35%),radial-gradient(circle_at_75%_30%,rgba(59,130,246,0.14),transparent_40%),radial-gradient(circle_at_50%_85%,rgba(16,185,129,0.10),transparent_45%)]" />
          <div className="absolute inset-0 opacity-40">
            <NetworkGrid />
          </div>

          <div className="relative flex h-full flex-col items-start justify-between p-8 lg:p-12">
            <div className="flex items-center gap-3">
              <div className={`rounded-2xl bg-zinc-950/50 p-3 ${brand.subtleGlow} border border-zinc-800/70`}>
                <Shield className="h-6 w-6 text-emerald-300" />
              </div>
              <div>
                <div className="text-lg font-semibold tracking-tight">MuWAF</div>
                <div className="text-sm text-zinc-400">Web Application Firewall · Admin Console</div>
              </div>
            </div>

            <div className="mt-10 w-full max-w-lg">
              <TerminalBoot />
            </div>

            <div className="mt-10 flex w-full items-center justify-between text-xs text-zinc-500">
              <div className="flex items-center gap-2">
                <span className="inline-flex h-2 w-2 animate-pulse rounded-full bg-emerald-400/80" />
                <span>Threat feed: Live</span>
              </div>
              <span className="opacity-80">v1.0 · Hardened UI</span>
            </div>
          </div>
        </div>

        {/* RIGHT: Login Form */}
        <div className="relative flex items-center justify-center p-6 lg:p-10">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_35%,rgba(24,24,27,0.55),transparent_55%)]" />

          {/* IP badge bottom-left */}
          <div className="pointer-events-none absolute bottom-4 left-4 hidden lg:block">
            <Badge
              variant="secondary"
              className="pointer-events-auto border border-zinc-800/70 bg-zinc-950/60 text-zinc-300"
            >
              {ipLabel}
            </Badge>
          </div>

          <div className="relative w-full max-w-md">
            {error && (
              <div className={shake ? "shake" : ""}>
                <Alert variant="destructive" className="mb-4 border-red-900/50 bg-red-950/30 text-red-300">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle>Erişim Reddedildi</AlertTitle>
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              </div>
            )}

            <Card className="border-zinc-800/70 bg-zinc-950/50 backdrop-blur">
              <CardHeader>
                <CardTitle className="text-2xl tracking-tight text-zinc-100">MuWAF Admin</CardTitle>
                <CardDescription className="text-zinc-400">
                  Sisteme erişmek için kimliğinizi doğrulayın
                </CardDescription>
              </CardHeader>

              <CardContent>
                <form onSubmit={onSubmitLogin} className="space-y-5">
                  <div className="space-y-2">
                    <Label htmlFor="username" className="text-zinc-300">Kullanıcı Adı</Label>
                    <Input
                      id="username"
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="admin"
                      className={`border-zinc-800/70 bg-zinc-950/70 text-zinc-100 placeholder:text-zinc-500 ${brand.ring}`}
                      autoComplete="username"
                      autoFocus
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="password" className="text-zinc-300">Şifre</Label>
                    <div className="relative">
                      <Input
                        id="password"
                        type={showPw ? "text" : "password"}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="••••••••"
                        className={`border-zinc-800/70 bg-zinc-950/70 pr-10 text-zinc-100 placeholder:text-zinc-500 ${brand.ring}`}
                        autoComplete="current-password"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPw((v) => !v)}
                        className="absolute inset-y-0 right-2 inline-flex items-center justify-center rounded-md px-2 text-zinc-400 hover:text-zinc-200 focus:outline-none"
                        aria-label={showPw ? "Şifreyi gizle" : "Şifreyi göster"}
                      >
                        {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>

                  <Button
                    type="submit"
                    className={`w-full ${brand.primaryBtn}`}
                    disabled={loading}
                  >
                    {loading ? (
                      <span className="inline-flex items-center gap-2">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Doğrulanıyor
                      </span>
                    ) : (
                      "Giriş Yap"
                    )}
                  </Button>

                  <div className="pt-2">
                    <Separator className="bg-zinc-800/70" />
                    <div className="mt-3 text-center text-xs text-zinc-500">
                      Kritik sistem · yalnızca yetkili personel erişebilir
                    </div>
                  </div>
                </form>
              </CardContent>
            </Card>

            <div className="mt-4 text-center text-xs text-zinc-500">
              &copy; {new Date().getFullYear()} MuWAF &middot; Audit logging enabled
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── Terminal Boot Animation ─── */
function TerminalBoot() {
  const script = useMemo(
    () =>
      [
        { kind: "muted", text: "MuWAF Secure Boot v1.0 (tty1)", delay: 120 },
        { kind: "muted", text: "Linux muwaf-gw 6.8.0-muwaf #1 SMP PREEMPT", delay: 90 },
        { kind: "muted", text: "", delay: 60 },
        { kind: "init", text: "[   0.321] ACPI: PM-Timer IO Port: 0x408", delay: 90 },
        { kind: "init", text: "[   0.842] kernel: Loading security policy...", delay: 140 },
        { kind: "ok", text: "[   1.104] systemd[1]: Detected virtualization oracle.", delay: 110 },
        { kind: "ok", text: "[   1.392] systemd[1]: Starting Network Manager...", delay: 160 },
        { kind: "ok", text: "[   1.771] systemd[1]: Started Network Manager.", delay: 120 },
        { kind: "info", text: "[   2.108] muwaf[core]: Neural-Link anomaly engine initialized.", delay: 180 },
        { kind: "info", text: "[   2.504] muwaf[crs]: Syncing OWASP Core Rule Set (CRS) v4.0...", delay: 420 },
        { kind: "ok", text: "[   2.936] muwaf[crs]: CRS synchronized (hash=8f3c…a21d).", delay: 150 },
        { kind: "info", text: "[   3.214] muwaf[dpi]: Deep Packet Inspection enabled on eth0.", delay: 380 },
        { kind: "warn", text: "[   3.612] muwaf[waf]: Blocked unauthorized probe from 185.x.x.x (rule=403.17).", delay: 260 },
        { kind: "ok", text: "[   3.924] muwaf[audit]: Audit trail active (sink=local+journal).", delay: 160 },
        { kind: "success", text: "[   4.211] muwaf: System hardened. Awaiting admin credentials…", delay: 220 },
      ] as const,
    []
  );

  const [lines, setLines] = useState<typeof script>([]);
  const [done, setDone] = useState(false);
  const endRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    const timers: number[] = [];

    setLines([]);
    setDone(false);

    const run = async () => {
      for (let i = 0; i < script.length; i++) {
        if (cancelled) return;
        const base = script[i].delay;
        const jitter = Math.floor(Math.random() * 90) - 30;
        const wait = Math.max(40, base + jitter);
        await new Promise<void>((resolve) => {
          const t = window.setTimeout(() => resolve(), wait);
          timers.push(t);
        });
        if (cancelled) return;
        setLines((prev) => [...prev, script[i]]);
      }
      if (!cancelled) setDone(true);
    };

    run();

    return () => {
      cancelled = true;
      timers.forEach((t) => window.clearTimeout(t));
    };
  }, [script]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "auto", block: "end" });
  }, [lines]);

  const cls = (kind: (typeof script)[number]["kind"]) => {
    switch (kind) {
      case "ok":
      case "success":
        return "text-emerald-500";
      case "warn":
        return "text-amber-500";
      case "info":
        return "text-zinc-300";
      case "muted":
        return "text-zinc-500";
      case "init":
      default:
        return "text-zinc-400";
    }
  };

  return (
    <div className="relative">
      <div className="absolute -inset-1 rounded-3xl bg-gradient-to-r from-emerald-400/10 via-sky-500/10 to-emerald-400/10 blur-2xl" />
      <Card className="relative overflow-hidden rounded-3xl border border-zinc-800 bg-zinc-950/50 backdrop-blur">
        {/* terminal chrome */}
        <div className="flex items-center justify-between border-b border-zinc-800/70 bg-zinc-950/30 px-4 py-2">
          <div className="flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
            <span className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
            <span className="h-2.5 w-2.5 rounded-full bg-zinc-700" />
          </div>
          <div className="font-mono text-xs text-zinc-500">console://muwaf</div>
          <div className="w-16" />
        </div>

        <CardContent className="pt-4">
          <div className="terminal h-56 overflow-auto rounded-2xl border border-zinc-800/70 bg-zinc-950/40 p-4 font-mono text-sm leading-6">
            {/* ASCII banner */}
            <div className="text-zinc-500">
              {"██╗   ██╗██╗    ██╗ █████╗ ███████╗"}
              <br />
              {"██║   ██║██║    ██║██╔══██╗██╔════╝"}
              <br />
              {"██║   ██║██║ █╗ ██║███████║█████╗  "}
              <br />
              {"██║   ██║██║███╗██║██╔══██║██╔══╝  "}
              <br />
              {"╚██████╔╝╚███╔███╔╝██║  ██║██║     "}
              <br />
              {" ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     "}
            </div>
            <div className="h-2" />

            {lines.map((l, idx) => (
              <div key={idx} className={cls(l.kind)}>
                {l.text}
              </div>
            ))}

            {/* Prompt */}
            <div className="mt-3 flex items-center gap-2">
              <span className="text-zinc-500">muwaf login:</span>
              <span className={done ? "cursor" : "cursor dim"} aria-hidden="true" />
            </div>
            <div ref={endRef} />
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-2">
            <Badge variant="secondary" className="border border-zinc-800/70 bg-zinc-950/50 text-zinc-300">
              Rate-limit
            </Badge>
            <Badge variant="secondary" className="border border-zinc-800/70 bg-zinc-950/50 text-zinc-300">
              Bot Mitigation
            </Badge>
            <Badge variant="secondary" className="border border-zinc-800/70 bg-zinc-950/50 text-zinc-300">
              Geo/IP Rules
            </Badge>
            <Badge variant="secondary" className="border border-zinc-800/70 bg-zinc-950/50 text-zinc-300">
              WAF Logs
            </Badge>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

/* ─── Animated Network Grid ─── */
function NetworkGrid() {
  return (
    <div className="absolute inset-0">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(255,255,255,0.06)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.06)_1px,transparent_1px)] bg-[size:44px_44px]" />

      <div className="absolute inset-0">
        <div className="traffic-line absolute left-[-20%] top-[18%] h-[2px] w-[140%]" />
        <div className="traffic-line absolute left-[-25%] top-[36%] h-[2px] w-[150%] [animation-delay:0.4s]" />
        <div className="traffic-line absolute left-[-30%] top-[54%] h-[2px] w-[160%] [animation-delay:0.8s]" />
        <div className="traffic-line absolute left-[-22%] top-[72%] h-[2px] w-[145%] [animation-delay:1.2s]" />
      </div>

      <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
        <div className="floaty relative">
          <div className="absolute -inset-8 rounded-full bg-emerald-400/10 blur-3xl" />
          <div className="absolute -inset-10 rounded-full bg-sky-500/10 blur-3xl" />
          <svg
            width="220"
            height="240"
            viewBox="0 0 220 240"
            className="relative"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
            aria-hidden="true"
          >
            <path
              d="M110 10C132 28 163 34 196 40V120C196 178 156 212 110 230C64 212 24 178 24 120V40C57 34 88 28 110 10Z"
              stroke="rgba(16,185,129,0.55)"
              strokeWidth="2"
            />
            <path
              d="M110 32C129 46 155 51 184 56V121C184 165 150 196 110 211C70 196 36 165 36 121V56C65 51 91 46 110 32Z"
              stroke="rgba(56,189,248,0.35)"
              strokeWidth="2"
            />
            <path d="M62 122H158" stroke="rgba(16,185,129,0.35)" strokeWidth="2" strokeLinecap="round" />
            <path d="M72 94H148" stroke="rgba(56,189,248,0.28)" strokeWidth="2" strokeLinecap="round" />
            <path d="M78 150H142" stroke="rgba(56,189,248,0.22)" strokeWidth="2" strokeLinecap="round" />
            <circle cx="110" cy="122" r="5" fill="rgba(16,185,129,0.6)" />
            <circle cx="110" cy="122" r="14" stroke="rgba(16,185,129,0.2)" />
            <circle cx="110" cy="122" r="24" stroke="rgba(56,189,248,0.14)" />
          </svg>
        </div>
      </div>
    </div>
  );
}

/* ─── CSS Animations ─── */
function StyleExtras() {
  return (
    <style>{`
      .shake { animation: shake 520ms ease-in-out; }
      @keyframes shake {
        0%, 100% { transform: translateX(0); }
        20% { transform: translateX(-6px); }
        40% { transform: translateX(6px); }
        60% { transform: translateX(-4px); }
        80% { transform: translateX(4px); }
      }

      .traffic-line {
        background: linear-gradient(90deg,
          rgba(16,185,129,0) 0%,
          rgba(16,185,129,0.20) 25%,
          rgba(56,189,248,0.25) 50%,
          rgba(16,185,129,0.20) 75%,
          rgba(16,185,129,0) 100%
        );
        filter: blur(0.2px);
        opacity: 0.9;
        animation: traffic 2.8s linear infinite;
      }
      @keyframes traffic {
        0% { transform: translateX(-18%); opacity: 0.25; }
        15% { opacity: 0.9; }
        70% { opacity: 0.8; }
        100% { transform: translateX(18%); opacity: 0.25; }
      }

      .floaty { animation: floaty 5.2s ease-in-out infinite; }
      @keyframes floaty {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-10px); }
      }

      .cursor {
        display: inline-block;
        width: 10px;
        height: 18px;
        border-radius: 2px;
        background: rgba(244,244,245,0.95);
        animation: blink 900ms step-end infinite;
      }
      .cursor.dim { opacity: 0.35; }
      @keyframes blink {
        0%, 50% { opacity: 1; }
        51%, 100% { opacity: 0; }
      }

      .terminal::-webkit-scrollbar { width: 10px; }
      .terminal::-webkit-scrollbar-track { background: rgba(24,24,27,0.35); }
      .terminal::-webkit-scrollbar-thumb { background: rgba(63,63,70,0.7); border-radius: 999px; }
      .terminal::-webkit-scrollbar-thumb:hover { background: rgba(82,82,91,0.8); }
    `}</style>
  );
}
