import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  CheckCircle2, XCircle, Clock, Loader, ChevronRight,
  ArrowLeft, Shield, Zap,
} from 'lucide-react';
import { Layout } from '@/components/ui/Layout';
import { Toast }  from '@/components/ui/Toast';
import api from '@/services/api';

/* ── Types ──────────────────────────────────────────────────────────── */
interface LiveVuln {
  id: string;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvssScore?: number;
  endpoint?: string;
  createdAt: string;
}
interface LiveModuleResult {
  id: string;
  moduleId: string;
  moduleName: string;
  moduleSlug: string;
  moduleDescription: string;
  moduleCategory: string;
  status: 'PENDING' | 'RUNNING' | 'DONE' | 'ERROR';
  executionTime?: number;
}
interface LiveStats {
  total: number;
  completed: number;
  errors: number;
  running: number;
  pending: number;
  progressPercent: number;
  vulnerabilitiesFound: { critical: number; high: number; medium: number; low: number };
}
interface LiveScanData {
  scan: {
    id: string;
    status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
    targetUrl: string;
    depth: string;
    threads: number;
    startedAt?: string;
    completedAt?: string;
    createdAt: string;
  };
  moduleResults: LiveModuleResult[];
  vulnerabilities: LiveVuln[];
  stats: LiveStats;
}

/* ── Severity config ─────────────────────────────────────────────── */
const SEV: Record<string, { label: string; bg: string; color: string }> = {
  CRITICAL: { label: 'CRITIQUE', bg: '#FFF0F0', color: '#FF6B6B' },
  HIGH:     { label: 'HAUTE',    bg: '#FFF7E6', color: '#FFB347' },
  MEDIUM:   { label: 'MOYENNE',  bg: '#F0EEFF', color: '#7C6FF7' },
  LOW:      { label: 'FAIBLE',   bg: '#E8FFFE', color: '#4ECDC4' },
};

/* ── Elapsed timer ───────────────────────────────────────────────── */
function useElapsedSeconds(startedAt?: string | null) {
  const [sec, setSec] = useState(0);
  useEffect(() => {
    if (!startedAt) return;
    const start = new Date(startedAt).getTime();
    const tick = () => setSec(Math.max(0, Math.floor((Date.now() - start) / 1000)));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [startedAt]);
  return sec;
}

function fmt(sec: number) {
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

/* ── Page ────────────────────────────────────────────────────────── */
export default function ScanLivePage() {
  const { id }   = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [toast,      setToast]      = useState<{ msg: string; type: 'success' | 'error' } | null>(null);
  const seenVulnIds = useRef<Set<string>>(new Set());
  const [newVulnIds, setNewVulnIds] = useState<Set<string>>(new Set());
  const feedRef     = useRef<HTMLDivElement>(null);

  /* ── Polling ─────────────────────────────────────────────────── */
  const { data, isLoading, error } = useQuery<{ data: { data: LiveScanData } }>({
    queryKey: ['scan-live', id],
    queryFn:  () => api.get(`/scans/${id}/live`),
    refetchInterval: (query) => {
      const status = query.state.data?.data?.data?.scan?.status;
      return status === 'RUNNING' || status === 'PENDING' ? 3000 : false;
    },
  });

  const live    = data?.data?.data;
  const scan    = live?.scan;
  const stats   = live?.stats;
  const modules = live?.moduleResults ?? [];
  const vulns   = live?.vulnerabilities ?? [];

  const elapsed = useElapsedSeconds(scan?.startedAt);
  const isDone  = scan?.status === 'COMPLETED' || scan?.status === 'FAILED';

  /* ── Detect new vulns, toast on CRITICAL ─────────────────────── */
  const vulnIdsStr = vulns.map(v => v.id).join(',');
  useEffect(() => {
    if (!vulns.length) return;
    const added: string[] = [];
    let firstCritical: LiveVuln | null = null;
    for (const v of vulns) {
      if (!seenVulnIds.current.has(v.id)) {
        seenVulnIds.current.add(v.id);
        added.push(v.id);
        if (!firstCritical && v.severity === 'CRITICAL') firstCritical = v;
      }
    }
    if (!added.length) return;
    setNewVulnIds(prev => new Set([...prev, ...added]));
    if (firstCritical) {
      setToast({ msg: `⚠️ Vulnérabilité critique : ${firstCritical.name}`, type: 'error' });
    }
    setTimeout(() => {
      if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }, 120);
  }, [vulnIdsStr]); // eslint-disable-line react-hooks/exhaustive-deps

  /* ── Cancel scan ─────────────────────────────────────────────── */
  const { mutate: cancelScan } = useMutation({
    mutationFn: () => api.delete(`/scans/${id}`),
    onSuccess:  () => navigate('/scans'),
  });

  /* ── Progress bar color ──────────────────────────────────────── */
  const pct = stats?.progressPercent ?? 0;
  const progressColor = !stats ? '#7C6FF7'
    : stats.vulnerabilitiesFound.critical > 0 ? '#FF6B6B'
    : stats.vulnerabilitiesFound.high     > 0 ? '#FFB347'
    : '#4ECDC4';

  /* ── Estimated remaining time ────────────────────────────────── */
  const estRemaining = pct > 0 && elapsed > 0 && !isDone
    ? Math.max(0, Math.round((elapsed / pct) * (100 - pct)))
    : null;

  /* ── Status badge config ─────────────────────────────────────── */
  const statusCfg = {
    COMPLETED: { label: 'Terminé',    bg: '#E8FFFE', color: '#4ECDC4', icon: <CheckCircle2 size={11} /> },
    RUNNING:   { label: 'En cours',   bg: '#F0EEFF', color: '#7C6FF7', icon: <Loader size={11} className="animate-spin" /> },
    FAILED:    { label: 'Échoué',     bg: '#FFF0F0', color: '#FF6B6B', icon: <XCircle size={11} /> },
    PENDING:   { label: 'En attente', bg: '#FFF7E6', color: '#FFB347', icon: <Clock size={11} /> },
  } as const;
  const sc = scan ? (statusCfg[scan.status] ?? statusCfg.PENDING) : statusCfg.PENDING;

  /* ── Loading / error states ──────────────────────────────────── */
  if (isLoading) return (
    <Layout>
      <div className="flex items-center justify-center" style={{ height: '60vh' }}>
        <Loader className="animate-spin" size={28} style={{ color: '#7C6FF7' }} />
      </div>
    </Layout>
  );
  if (error || !scan) return (
    <Layout>
      <div className="text-center py-16" style={{ color: '#6B6B8A' }}>Scan introuvable.</div>
    </Layout>
  );

  return (
    <Layout>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

      {/* ── Top bar ───────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-8 py-4 bg-white"
           style={{ borderBottom: '1px solid #EDE8FF' }}>
        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/scans')}
                  className="flex items-center gap-1 text-sm font-medium"
                  style={{ color: '#6B6B8A' }}>
            <ArrowLeft size={15} /> Mes scans
          </button>
          <span style={{ color: '#EDE8FF' }}>|</span>
          <h1 className="font-bold text-navy text-base">Scan en cours</h1>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold"
                style={{ background: sc.bg, color: sc.color }}>
            {sc.icon} {sc.label}
          </span>
        </div>

        <div className="flex items-center gap-3">
          {/* Elapsed timer */}
          {scan.startedAt && (
            <div className="flex items-center gap-1.5 font-mono text-sm" style={{ color: '#6B6B8A' }}>
              <Clock size={13} />
              {fmt(elapsed)}
              {estRemaining != null && (
                <span className="text-xs font-sans ml-1" style={{ color: '#9ca3af' }}>
                  (~{fmt(estRemaining)} restant)
                </span>
              )}
            </div>
          )}

          {!isDone ? (
            <button
              onClick={() => { if (window.confirm('Annuler et supprimer ce scan ?')) cancelScan(); }}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm font-semibold"
              style={{ background: '#FFF0F0', color: '#FF6B6B', border: '1px solid #FFD0D0' }}>
              <XCircle size={14} /> Annuler
            </button>
          ) : (
            <button onClick={() => navigate(`/scans/${id}/results`)}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-bold text-white"
                    style={{ background: scan.status === 'FAILED' ? '#FF6B6B' : '#7C6FF7' }}>
              Voir les résultats <ChevronRight size={14} />
            </button>
          )}
        </div>
      </div>

      <div className="px-8 py-5">

        {/* ── Global progress bar ───────────────────────────────── */}
        <div className="bg-white rounded-2xl p-5 mb-5" style={{ border: '1px solid #EDE8FF' }}>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2 min-w-0">
              <Shield size={15} style={{ color: '#7C6FF7', flexShrink: 0 }} />
              <span className="font-mono text-sm text-navy truncate">{scan.targetUrl}</span>
            </div>
            <div className="flex items-center gap-4 shrink-0 ml-3">
              {stats && stats.vulnerabilitiesFound.critical > 0 && (
                <span className="text-xs font-semibold" style={{ color: '#FF6B6B' }}>
                  🔴 {stats.vulnerabilitiesFound.critical} critique{stats.vulnerabilitiesFound.critical > 1 ? 's' : ''}
                </span>
              )}
              {stats && stats.vulnerabilitiesFound.high > 0 && (
                <span className="text-xs font-semibold" style={{ color: '#FFB347' }}>
                  🟠 {stats.vulnerabilitiesFound.high} haute{stats.vulnerabilitiesFound.high > 1 ? 's' : ''}
                </span>
              )}
              <span className="font-mono font-bold text-sm" style={{ color: progressColor }}>{pct}%</span>
            </div>
          </div>

          <div className="w-full rounded-full h-3 overflow-hidden" style={{ background: '#EDE8FF' }}>
            <div className="h-3 rounded-full transition-all duration-700 relative overflow-hidden"
                 style={{ width: `${pct}%`, background: progressColor }}>
              {!isDone && pct > 0 && (
                <div className="absolute inset-0" style={{
                  background: 'linear-gradient(90deg, transparent, rgba(255,255,255,.45), transparent)',
                  backgroundSize: '200% 100%',
                  animation: 'shimmer 2s linear infinite',
                }} />
              )}
            </div>
          </div>

          <div className="flex items-center justify-between mt-2 text-xs" style={{ color: '#6B6B8A' }}>
            <span>{(stats?.completed ?? 0) + (stats?.errors ?? 0)}/{stats?.total ?? 0} modules terminés</span>
            {stats && stats.errors > 0 && (
              <span style={{ color: '#FF6B6B' }}>{stats.errors} erreur{stats.errors > 1 ? 's' : ''}</span>
            )}
          </div>
        </div>

        {/* ── 2-column layout ───────────────────────────────────── */}
        <div style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', gap: '20px' }}>

          {/* LEFT — Modules list (60%) */}
          <div className="bg-white rounded-2xl overflow-hidden" style={{ border: '1px solid #EDE8FF' }}>
            <div className="px-5 py-3.5" style={{ borderBottom: '1px solid #EDE8FF' }}>
              <h2 className="text-sm font-semibold text-navy">Modules d'analyse</h2>
            </div>

            {modules.length === 0 ? (
              <div className="px-5 py-10 text-center">
                <Loader size={20} className="animate-spin mx-auto mb-2" style={{ color: '#7C6FF7' }} />
                <p className="text-sm" style={{ color: '#6B6B8A' }}>Initialisation des modules…</p>
              </div>
            ) : (
              <div>
                {modules.map((m, i) => {
                  const isRun  = m.status === 'RUNNING';
                  const isDoneM = m.status === 'DONE';
                  const isErr  = m.status === 'ERROR';

                  const stCfg = isRun
                    ? { bg: '#F0EEFF', color: '#7C6FF7', label: 'En cours',  icon: <Loader size={13} className="animate-spin" /> }
                    : isDoneM
                    ? { bg: '#E8FFFE', color: '#4ECDC4', label: 'Terminé',   icon: <CheckCircle2 size={13} /> }
                    : isErr
                    ? { bg: '#FFF0F0', color: '#FF6B6B', label: 'Erreur',    icon: <XCircle size={13} /> }
                    : { bg: '#F8F6FF', color: '#9ca3af', label: 'En attente', icon: <Clock size={13} /> };

                  return (
                    <div key={m.id}
                         className="px-5 py-4 transition-colors"
                         style={{
                           borderBottom: i < modules.length - 1 ? '1px solid #F8F6FF' : 'none',
                           background:   isRun ? 'rgba(124,111,247,0.03)' : 'transparent',
                         }}>
                      <div className="flex items-center gap-3">
                        {/* Status icon */}
                        <div className="shrink-0 w-8 h-8 rounded-lg flex items-center justify-center"
                             style={{ background: stCfg.bg, color: stCfg.color }}>
                          {stCfg.icon}
                        </div>

                        {/* Name + description */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="text-sm font-semibold text-navy">{m.moduleName}</p>
                            {isRun && (
                              <span className="relative flex h-2 w-2 shrink-0">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75"
                                      style={{ background: '#7C6FF7' }} />
                                <span className="relative inline-flex rounded-full h-2 w-2"
                                      style={{ background: '#7C6FF7' }} />
                              </span>
                            )}
                          </div>
                          <p className="text-xs mt-0.5 truncate" style={{ color: '#9ca3af' }}>
                            {m.moduleDescription}
                          </p>
                        </div>

                        {/* Right: exec time + status badge */}
                        <div className="shrink-0 flex items-center gap-2 ml-2">
                          {m.executionTime != null && isDoneM && (
                            <span className="font-mono text-xs" style={{ color: '#9ca3af' }}>
                              {(m.executionTime / 1000).toFixed(1)}s
                            </span>
                          )}
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold"
                                style={{ background: stCfg.bg, color: stCfg.color }}>
                            {stCfg.icon}
                            {stCfg.label}
                          </span>
                        </div>
                      </div>

                      {/* Indeterminate progress bar while running */}
                      {isRun && (
                        <div className="mt-2 ml-11 overflow-hidden rounded-full h-1"
                             style={{ background: '#EDE8FF' }}>
                          <div className="h-1 rounded-full"
                               style={{ width: '40%', background: '#7C6FF7', animation: 'indeterminate 1.8s ease-in-out infinite' }} />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* RIGHT — Live vuln feed (40%) */}
          <div className="bg-white rounded-2xl flex flex-col overflow-hidden"
               style={{ border: '1px solid #EDE8FF', maxHeight: 'calc(100vh - 230px)' }}>

            {/* Feed header */}
            <div className="px-5 py-3.5 shrink-0" style={{ borderBottom: '1px solid #EDE8FF' }}>
              <div className="flex items-center gap-2 mb-2.5">
                <Zap size={14} style={{ color: '#FF6B6B' }} />
                <h2 className="text-sm font-semibold text-navy">Vulnérabilités découvertes</h2>
              </div>
              {/* Severity counters */}
              <div className="flex gap-3">
                {[
                  { emoji: '🔴', count: stats?.vulnerabilitiesFound.critical ?? 0, color: '#FF6B6B' },
                  { emoji: '🟠', count: stats?.vulnerabilitiesFound.high     ?? 0, color: '#FFB347' },
                  { emoji: '🟡', count: stats?.vulnerabilitiesFound.medium   ?? 0, color: '#7C6FF7' },
                  { emoji: '🟢', count: stats?.vulnerabilitiesFound.low      ?? 0, color: '#4ECDC4' },
                ].map((s, i) => (
                  <div key={i} className="flex items-center gap-1 text-xs">
                    <span>{s.emoji}</span>
                    <span className="font-mono font-bold" style={{ color: s.color }}>{s.count}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Scrollable feed */}
            <div ref={feedRef} className="flex-1 overflow-y-auto p-3 space-y-2 min-h-0">
              {vulns.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full py-10 text-center">
                  <div className="relative mb-3">
                    <Shield size={30} style={{ color: '#EDE8FF' }} />
                    {!isDone && (
                      <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full animate-pulse"
                           style={{ background: '#7C6FF7' }} />
                    )}
                  </div>
                  <p className="text-sm font-medium" style={{ color: '#6B6B8A' }}>
                    {isDone ? 'Aucune vulnérabilité détectée' : 'Analyse en cours…'}
                  </p>
                  {!isDone && (
                    <p className="text-xs mt-1" style={{ color: '#9ca3af' }}>
                      Les résultats apparaissent ici en direct
                    </p>
                  )}
                </div>
              ) : (
                vulns.map(v => {
                  const s = SEV[v.severity] ?? SEV.LOW;
                  const isNew = newVulnIds.has(v.id);
                  return (
                    <div key={v.id}
                         className="rounded-xl p-3"
                         style={{
                           border:    `1px solid ${s.color}30`,
                           background: s.bg,
                           animation:  isNew ? 'slideUp 0.3s ease-out' : 'none',
                         }}>
                      <div className="flex items-center gap-1.5 mb-1.5">
                        <span className="inline-flex px-1.5 py-0.5 rounded text-[9px] font-black"
                              style={{ background: s.color, color: '#fff' }}>
                          {s.label}
                        </span>
                        {v.cvssScore != null && (
                          <span className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded"
                                style={{ background: '#1C1C2E', color: '#4ECDC4' }}>
                            {v.cvssScore.toFixed(1)}
                          </span>
                        )}
                      </div>
                      <p className="text-xs font-semibold text-navy leading-snug">{v.name}</p>
                      {v.endpoint && (
                        <p className="font-mono text-[10px] mt-1 truncate" style={{ color: '#9ca3af' }}>
                          {v.endpoint}
                        </p>
                      )}
                    </div>
                  );
                })
              )}
            </div>

            {/* Live indicator footer */}
            {!isDone && (
              <div className="px-5 py-2 shrink-0 text-center"
                   style={{ borderTop: '1px solid #EDE8FF' }}>
                <div className="flex items-center justify-center gap-1.5 text-[10px]"
                     style={{ color: '#9ca3af' }}>
                  <div className="w-1.5 h-1.5 rounded-full animate-pulse"
                       style={{ background: '#7C6FF7' }} />
                  Mise à jour en temps réel · toutes les 3s
                </div>
              </div>
            )}
          </div>

        </div>
      </div>

      {/* CSS animations */}
      <style>{`
        @keyframes shimmer {
          0%   { background-position: -200% 0; }
          100% { background-position:  200% 0; }
        }
        @keyframes slideUp {
          from { opacity: 0; transform: translateY(10px); }
          to   { opacity: 1; transform: translateY(0);    }
        }
        @keyframes indeterminate {
          0%   { transform: translateX(-150%); }
          100% { transform: translateX(400%);  }
        }
      `}</style>
    </Layout>
  );
}
