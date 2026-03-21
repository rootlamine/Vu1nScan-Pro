import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  Search, AlertTriangle, Clock, CheckCircle2,
  ChevronRight, Eye, Trash2, Loader,
  XCircle, Circle, type LucideIcon,
} from 'lucide-react';
import { Layout, TopBar } from '@/components/ui/Layout';
import api from '@/services/api';
import type { PaginatedScans, Scan, VulnStats } from '@/types';

/* ── helpers ──────────────────────────────────────────────────────── */
function statusPill(status: Scan['status']) {
  const cfg = {
    COMPLETED: { label: 'Terminé',    bg: '#E8FFFE', color: '#4ECDC4', Icon: CheckCircle2 },
    RUNNING:   { label: 'En cours',   bg: '#F0EEFF', color: '#7C6FF7', Icon: Loader       },
    FAILED:    { label: 'Échoué',     bg: '#FFF0F0', color: '#FF6B6B', Icon: XCircle      },
    PENDING:   { label: 'En attente', bg: '#FFF7E6', color: '#FFB347', Icon: Clock        },
  } as const;
  const c = cfg[status] ?? cfg.PENDING;
  const Icon = c.Icon;
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold"
          style={{ background: c.bg, color: c.color }}>
      {status === 'RUNNING'
        ? <Loader size={11} className="animate-spin" />
        : <Icon size={11} />}
      {c.label}
    </span>
  );
}

function severityBadge(sev: string, count: number) {
  const cfg: Record<string, { bg: string; color: string; label: string }> = {
    CRITICAL: { bg: '#FF6B6B', color: '#fff', label: 'CRIT' },
    HIGH:     { bg: '#FFB347', color: '#fff', label: 'HIGH' },
    MEDIUM:   { bg: '#7C6FF7', color: '#fff', label: 'MED'  },
    LOW:      { bg: '#4ECDC4', color: '#fff', label: 'LOW'  },
  };
  const c = cfg[sev];
  if (!c || count === 0) return null;
  return (
    <span key={sev} className="font-mono text-[10px] font-bold px-1.5 py-0.5 rounded"
          style={{ background: c.bg, color: c.color }}>
      {count} {c.label}
    </span>
  );
}

/* ── KPI card ─────────────────────────────────────────────────────── */
function KpiCard({
  icon: Icon, iconBg, iconColor, value, label, badge, badgeColor, topColor,
}: {
  icon: LucideIcon; iconBg: string; iconColor: string;
  value: string | number; label: string;
  badge?: string; badgeColor?: string; topColor: string;
}) {
  return (
    <div className="bg-white rounded-2xl p-5 flex flex-col gap-3 relative overflow-hidden"
         style={{ border: '1px solid #EDE8FF' }}>
      <div className="absolute top-0 left-0 right-0 h-0.5 rounded-t-2xl"
           style={{ background: topColor }} />
      <div className="flex items-start justify-between">
        <div className="w-9 h-9 rounded-xl flex items-center justify-center"
             style={{ background: iconBg }}>
          <Icon size={17} style={{ color: iconColor }} />
        </div>
        {badge && (
          <span className="text-[11px] font-semibold px-2 py-0.5 rounded-full"
                style={{ background: `${badgeColor}18`, color: badgeColor }}>
            {badge}
          </span>
        )}
      </div>
      <div>
        <p className="font-mono font-bold text-2xl text-navy">{value}</p>
        <p className="text-xs mt-0.5" style={{ color: '#6B6B8A' }}>{label}</p>
      </div>
    </div>
  );
}

/* ── Severity bar ─────────────────────────────────────────────────── */
function SevBar({ label, count, max, color, icon: Icon }: {
  label: string; count: number; max: number;
  color: string; icon: LucideIcon;
}) {
  const pct = max > 0 ? (count / max) * 100 : 0;
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <div className="flex items-center gap-1.5">
          <Icon size={13} style={{ color }} />
          <span className="text-sm font-medium" style={{ color }}>{label}</span>
        </div>
        <span className="font-mono text-sm font-bold text-navy">{count}</span>
      </div>
      <div className="w-full rounded-full h-2" style={{ background: '#F0EEFF' }}>
        <div className="h-2 rounded-full transition-all duration-700"
             style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

/* ── Page ─────────────────────────────────────────────────────────── */
export default function DashboardPage() {
  const navigate = useNavigate();

  const today = new Date().toLocaleDateString('fr-FR', {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
  });

  const { data, isLoading } = useQuery<{ data: { data: PaginatedScans } }>({
    queryKey: ['scans', 'dashboard'],
    queryFn:  () => api.get('/scans?limit=5&page=1'),
  });

  const { data: statsData } = useQuery<{ data: { data: { critical: number; high: number; medium: number; low: number; total: number } } }>({
    queryKey: ['global-stats'],
    queryFn:  () => api.get('/vulnerabilities/stats').catch(() => ({ data: { data: { critical: 0, high: 0, medium: 0, low: 0, total: 0 } } })),
  });

  const scans     = data?.data?.data?.scans ?? [];
  const total     = data?.data?.data?.total ?? 0;
  const completed = scans.filter(s => s.status === 'COMPLETED').length;
  const running   = scans.filter(s => s.status === 'RUNNING' || s.status === 'PENDING').length;

  const sevStats = statsData?.data?.data ?? { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  const sevMax = Math.max(sevStats.critical, sevStats.high, sevStats.medium, sevStats.low, 1);

  const completedPct = total > 0 ? Math.round((completed / total) * 100) : 0;

  return (
    <Layout>
      <TopBar
        title="Dashboard"
        subtitle={`${today.charAt(0).toUpperCase() + today.slice(1)} — Vue d'ensemble de la plateforme`}
      />

      <div className="px-8 py-6 flex gap-6">
        {/* ── Colonne principale ─────────────────────────────────── */}
        <div className="flex-1 min-w-0 space-y-6">

          {/* Section label */}
          <div>
            <p className="text-xs font-bold tracking-widest uppercase mb-4"
               style={{ color: '#6B6B8A' }}>
              Vue d'ensemble
            </p>

            {/* KPI Grid */}
            <div className="grid grid-cols-4 gap-4">
              <KpiCard
                icon={Search} iconBg="#F0EEFF" iconColor="#7C6FF7"
                value={total} label="Total scans réalisés"
                badge="+12%" badgeColor="#4ECDC4" topColor="#7C6FF7"
              />
              <KpiCard
                icon={AlertTriangle} iconBg="#FFF0F0" iconColor="#FF6B6B"
                value={sevStats.total.toLocaleString('fr-FR')} label="Vulnérabilités détectées"
                badge="+34" badgeColor="#FF6B6B" topColor="#FF6B6B"
              />
              <KpiCard
                icon={Clock} iconBg="#FFF7E6" iconColor="#FFB347"
                value={running} label="Scans actifs en cours"
                badge={running > 0 ? 'En cours' : undefined} badgeColor="#FFB347" topColor="#FFB347"
              />
              <KpiCard
                icon={CheckCircle2} iconBg="#E8FFFE" iconColor="#4ECDC4"
                value={`${completedPct}%`} label="Taux de complétion"
                badge="+4%" badgeColor="#4ECDC4" topColor="#4ECDC4"
              />
            </div>
          </div>

          {/* Scans récents */}
          <div className="bg-white rounded-2xl overflow-hidden" style={{ border: '1px solid #EDE8FF' }}>
            <div className="px-6 py-4 flex items-center justify-between"
                 style={{ borderBottom: '1px solid #EDE8FF' }}>
              <div>
                <h2 className="font-bold text-navy text-sm">Scans récents</h2>
                <p className="text-xs mt-0.5" style={{ color: '#6B6B8A' }}>
                  5 derniers — cliquez pour voir les résultats
                </p>
              </div>
              <button
                onClick={() => navigate('/scans')}
                className="flex items-center gap-1 text-xs font-semibold transition-all"
                style={{ color: '#7C6FF7' }}
              >
                Voir tous <ChevronRight size={14} />
              </button>
            </div>

            {/* Table header */}
            <div className="grid gap-4 px-6 py-2.5 text-[10px] font-bold uppercase tracking-wider"
                 style={{
                   gridTemplateColumns: '2fr 1fr 1.5fr 1fr auto',
                   background: '#FAFAFA', borderBottom: '1px solid #EDE8FF', color: '#6B6B8A',
                 }}>
              <div>URL Cible</div>
              <div>Statut</div>
              <div>Résultats</div>
              <div>Date</div>
              <div />
            </div>

            {isLoading ? (
              <div className="py-10 flex justify-center">
                <Loader size={22} className="animate-spin" style={{ color: '#7C6FF7' }} />
              </div>
            ) : scans.length === 0 ? (
              <div className="py-12 text-center">
                <Search size={24} className="mx-auto mb-3" style={{ color: '#EDE8FF' }} />
                <p className="text-sm font-medium text-navy">Aucun scan pour l'instant</p>
                <button
                  onClick={() => navigate('/scans/new')}
                  className="mt-3 px-4 py-2 rounded-xl text-sm font-semibold text-white"
                  style={{ background: '#FF6B6B' }}
                >
                  Lancer un scan
                </button>
              </div>
            ) : (
              scans.map(scan => (
                <div
                  key={scan.id}
                  className="grid gap-4 px-6 py-3.5 cursor-pointer group transition-all"
                  style={{
                    gridTemplateColumns: '2fr 1fr 1.5fr 1fr auto',
                    borderBottom: '1px solid #F8F6FF',
                  }}
                  onClick={() => navigate(
                    scan.status === 'COMPLETED' || scan.status === 'FAILED'
                      ? `/scans/${scan.id}/results`
                      : `/scans/${scan.id}/live`
                  )}
                  onMouseEnter={e => (e.currentTarget.style.background = '#FAFAFE')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <div className="min-w-0">
                    <p className="font-mono text-sm font-semibold text-navy truncate">
                      {scan.targetUrl.replace(/^https?:\/\//, '')}
                    </p>
                    <p className="text-[11px] mt-0.5" style={{ color: '#6B6B8A' }}>
                      {scan.moduleResults
                        ? `${scan.moduleResults.length} modules`
                        : 'modules'
                      } · {scan.status === 'COMPLETED' && scan.completedAt && scan.startedAt
                        ? `${Math.round((new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime()) / 60000)} min`
                        : scan.depth
                      }
                    </p>
                  </div>
                  <div className="flex items-center">{statusPill(scan.status)}</div>
                  <div className="flex items-center gap-1 flex-wrap">
                    {/* Placeholder severity counts — real data needs vuln endpoint */}
                    <span className="text-xs" style={{ color: '#6B6B8A' }}>—</span>
                  </div>
                  <div className="flex items-center text-xs" style={{ color: '#6B6B8A' }}>
                    {timeAgo(scan.createdAt)}
                  </div>
                  <div className="flex items-center gap-2">
                    <button className="opacity-0 group-hover:opacity-100 transition-all"
                            style={{ color: '#6B6B8A' }}
                            title="Voir" onClick={e => { e.stopPropagation(); }}>
                      <Eye size={14} />
                    </button>
                    <button className="opacity-0 group-hover:opacity-100 transition-all"
                            style={{ color: '#6B6B8A' }}
                            title="Supprimer" onClick={e => e.stopPropagation()}>
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* ── Colonne droite ─────────────────────────────────────── */}
        <div className="w-[280px] shrink-0 space-y-5">

          {/* Répartition sévérités */}
          <div className="bg-white rounded-2xl p-5" style={{ border: '1px solid #EDE8FF' }}>
            <h3 className="font-bold text-navy text-sm mb-0.5">Répartition sévérités</h3>
            <p className="text-xs mb-4" style={{ color: '#6B6B8A' }}>Sur les 30 derniers jours</p>
            <div className="space-y-3">
              <SevBar label="Critique" count={sevStats.critical} max={sevMax} color="#FF6B6B" icon={Circle} />
              <SevBar label="Haute"    count={sevStats.high}     max={sevMax} color="#FFB347" icon={AlertTriangle} />
              <SevBar label="Moyenne"  count={sevStats.medium}   max={sevMax} color="#7C6FF7" icon={Circle} />
              <SevBar label="Faible"   count={sevStats.low}      max={sevMax} color="#4ECDC4" icon={CheckCircle2} />
            </div>
          </div>

          {/* Vulnérabilités récentes */}
          <div className="bg-white rounded-2xl p-5" style={{ border: '1px solid #EDE8FF' }}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-navy text-sm">Vulnérabilités récentes</h3>
              <button className="text-xs font-semibold" style={{ color: '#7C6FF7' }}
                      onClick={() => navigate('/vulnerabilities')}>
                Voir
              </button>
            </div>
            <RecentVulns />
          </div>

          {/* Modules de scan */}
          <div className="bg-white rounded-2xl p-5" style={{ border: '1px solid #EDE8FF' }}>
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-navy text-sm">Modules de scan</h3>
              <button className="text-xs font-semibold" style={{ color: '#7C6FF7' }}
                      onClick={() => navigate('/admin/modules')}>
                Gérer
              </button>
            </div>
            <ModuleChips />
          </div>
        </div>
      </div>
    </Layout>
  );
}

/* ── helpers ──────────────────────────────────────────────────────── */
function timeAgo(dateStr: string) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 60) return `Il y a ${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `Il y a ${h}h`;
  const d = Math.floor(h / 24);
  if (d === 1) return 'Hier';
  if (d < 7) return `Il y a ${d}j`;
  return new Date(dateStr).toLocaleDateString('fr-FR');
}

function RecentVulns() {
  const { data } = useQuery<{ data: { data: Array<{ id: string; name: string; endpoint?: string; cvssScore?: number; severity: string }> } }>({
    queryKey: ['recent-vulns'],
    queryFn:  () => api.get('/vulnerabilities?limit=3').catch(() => ({ data: { data: [] } })),
  });
  const vulns = data?.data?.data ?? [];
  const SEV_ICON: Record<string, { bg: string; color: string }> = {
    CRITICAL: { bg: '#FFF0F0', color: '#FF6B6B' },
    HIGH:     { bg: '#FFF7E6', color: '#FFB347' },
    MEDIUM:   { bg: '#F0EEFF', color: '#7C6FF7' },
    LOW:      { bg: '#E8FFFE', color: '#4ECDC4' },
  };
  if (vulns.length === 0) return <p className="text-xs" style={{ color: '#6B6B8A' }}>Aucune vulnérabilité récente</p>;
  return (
    <div className="space-y-3">
      {vulns.map(v => {
        const c = SEV_ICON[v.severity] ?? SEV_ICON.LOW;
        return (
          <div key={v.id} className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                 style={{ background: c.bg }}>
              <AlertTriangle size={14} style={{ color: c.color }} />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-navy truncate">{v.name}</p>
              <p className="text-[11px] font-mono truncate" style={{ color: '#6B6B8A' }}>
                {v.endpoint?.replace(/^https?:\/\//, '')}
              </p>
            </div>
            {v.cvssScore != null && (
              <span className="font-mono text-xs font-bold shrink-0"
                    style={{ color: c.color }}>
                {v.cvssScore.toFixed(1)}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}

function ModuleChips() {
  const { data } = useQuery<{ data: { data: Array<{ id: string; name: string; isActive: boolean }> } }>({
    queryKey: ['modules'],
    queryFn:  () => api.get('/modules'),
  });
  const modules = data?.data?.data ?? [];
  return (
    <div className="flex flex-wrap gap-2">
      {modules.slice(0, 6).map(m => (
        <div key={m.id} className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-medium"
             style={{ background: '#F0EEFF', color: '#7C6FF7' }}>
          <span className="w-1.5 h-1.5 rounded-full inline-block"
                style={{ background: m.isActive ? '#4ECDC4' : '#6B6B8A' }} />
          {m.name}
        </div>
      ))}
    </div>
  );
}
