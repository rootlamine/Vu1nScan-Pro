import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, Legend,
} from 'recharts';
import {
  Search, AlertTriangle, Clock, CheckCircle2,
  ChevronRight, Eye, Loader,
  XCircle, TrendingUp, TrendingDown, Minus,
  type LucideIcon,
} from 'lucide-react';
import { Layout, TopBar } from '@/components/ui/Layout';
import api from '@/services/api';
import type { PaginatedScans, Scan } from '@/types';

/* ── types ──────────────────────────────────────────────────────────── */
interface DashboardStats {
  kpis: {
    totalScans: number; totalVulns: number; activeScans: number; completionRate: number;
    weeklyScans: number; weeklyVulns: number;
    deltaScans: number | null; deltaVulns: number | null;
  };
  scanHistory:          Array<{ date: string; count: number }>;
  severityDistribution: Array<{ name: string; value: number }>;
  moduleInsights:       Array<{ name: string; category: string; detectionRate: number; avgTime: number; runCount: number }>;
}

/* ── helpers ────────────────────────────────────────────────────────── */
function timeAgo(dateStr: string) {
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'À l\'instant';
  if (m < 60) return `Il y a ${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `Il y a ${h}h`;
  const d = Math.floor(h / 24);
  if (d === 1) return 'Hier';
  return new Date(dateStr).toLocaleDateString('fr-FR');
}

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
      {status === 'RUNNING' ? <Loader size={11} className="animate-spin" /> : <Icon size={11} />}
      {c.label}
    </span>
  );
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#FF6B6B', HIGH: '#FFB347', MEDIUM: '#7C6FF7', LOW: '#4ECDC4',
};
const SEV_LABELS: Record<string, string> = {
  CRITICAL: 'Critique', HIGH: 'Élevé', MEDIUM: 'Moyen', LOW: 'Faible',
};

/* ── KPI card ───────────────────────────────────────────────────────── */
function KpiCard({
  icon: Icon, iconBg, iconColor, value, label, delta, topColor,
}: {
  icon: LucideIcon; iconBg: string; iconColor: string;
  value: string | number; label: string;
  delta?: number | null; topColor: string;
}) {
  const DeltaIcon = delta == null ? null : delta > 0 ? TrendingUp : delta < 0 ? TrendingDown : Minus;
  const deltaColor = delta == null ? undefined : delta > 0 ? '#4ECDC4' : delta < 0 ? '#FF6B6B' : '#6B6B8A';
  return (
    <div className="bg-white rounded-2xl p-5 flex flex-col gap-3 relative overflow-hidden"
         style={{ border: '1px solid #EDE8FF' }}>
      <div className="absolute top-0 left-0 right-0 h-0.5 rounded-t-2xl" style={{ background: topColor }} />
      <div className="flex items-start justify-between">
        <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ background: iconBg }}>
          <Icon size={17} style={{ color: iconColor }} />
        </div>
        {DeltaIcon && delta != null && (
          <span className="flex items-center gap-0.5 text-[11px] font-semibold px-2 py-0.5 rounded-full"
                style={{ background: `${deltaColor}18`, color: deltaColor }}>
            <DeltaIcon size={10} />{Math.abs(delta)}%
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

/* ── Page ───────────────────────────────────────────────────────────── */
export default function DashboardPage() {
  const navigate = useNavigate();

  const today = new Date().toLocaleDateString('fr-FR', {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
  });

  const { data: scansData, isLoading: scansLoading } = useQuery<{ data: { data: PaginatedScans } }>({
    queryKey: ['scans', 'dashboard'],
    queryFn:  () => api.get('/scans?limit=5&page=1'),
  });

  const { data: dashData, isLoading: dashLoading } = useQuery<{ data: { data: DashboardStats } }>({
    queryKey: ['dashboard-stats'],
    queryFn:  () => api.get('/dashboard/stats'),
    refetchInterval: 30_000,
  });

  const scans = scansData?.data?.data?.scans ?? [];
  const stats = dashData?.data?.data;
  const kpis  = stats?.kpis;

  // Format date labels for chart (DD/MM)
  const scanHistory = (stats?.scanHistory ?? []).map(d => ({
    ...d,
    label: new Date(d.date).toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit' }),
  }));

  return (
    <Layout>
      <TopBar
        title="Dashboard"
        subtitle={`${today.charAt(0).toUpperCase() + today.slice(1)} — Vue d'ensemble`}
      />

      <div className="px-8 py-6 space-y-6">

        {/* ── KPI Grid ───────────────────────────────────────────────── */}
        <div className="grid grid-cols-4 gap-4">
          <KpiCard
            icon={Search} iconBg="#F0EEFF" iconColor="#7C6FF7"
            value={kpis?.totalScans ?? '—'} label="Total scans réalisés"
            delta={kpis?.deltaScans} topColor="#7C6FF7"
          />
          <KpiCard
            icon={AlertTriangle} iconBg="#FFF0F0" iconColor="#FF6B6B"
            value={kpis?.totalVulns?.toLocaleString('fr-FR') ?? '—'} label="Vulnérabilités détectées"
            delta={kpis?.deltaVulns} topColor="#FF6B6B"
          />
          <KpiCard
            icon={Clock} iconBg="#FFF7E6" iconColor="#FFB347"
            value={kpis?.activeScans ?? '—'} label="Scans actifs en cours"
            topColor="#FFB347"
          />
          <KpiCard
            icon={CheckCircle2} iconBg="#E8FFFE" iconColor="#4ECDC4"
            value={kpis ? `${kpis.completionRate}%` : '—'} label="Taux de complétion"
            topColor="#4ECDC4"
          />
        </div>

        {/* ── Charts row ─────────────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-5">

          {/* Line chart — scans/jour (30j) */}
          <div className="col-span-2 bg-white rounded-2xl p-5" style={{ border: '1px solid #EDE8FF' }}>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="font-bold text-navy text-sm">Activité des scans</h3>
                <p className="text-xs" style={{ color: '#6B6B8A' }}>30 derniers jours</p>
              </div>
              <div className="flex items-center gap-2 text-xs font-semibold"
                   style={{ color: kpis?.deltaScans != null && kpis.deltaScans >= 0 ? '#4ECDC4' : '#FF6B6B' }}>
                {kpis?.weeklyScans ?? 0} cette semaine
              </div>
            </div>
            {dashLoading ? (
              <div className="h-44 flex items-center justify-center">
                <Loader size={22} className="animate-spin" style={{ color: '#7C6FF7' }} />
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <LineChart data={scanHistory} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#F0EEFF" />
                  <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#6B6B8A' }} tickLine={false} interval={4} />
                  <YAxis tick={{ fontSize: 10, fill: '#6B6B8A' }} tickLine={false} axisLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ border: '1px solid #EDE8FF', borderRadius: 8, fontSize: 12 }}
                    labelStyle={{ color: '#1C1C2E', fontWeight: 600 }}
                  />
                  <Line type="monotone" dataKey="count" stroke="#7C6FF7" strokeWidth={2.5}
                        dot={false} activeDot={{ r: 4, fill: '#7C6FF7' }} name="Scans" />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Pie chart — sévérités */}
          <div className="bg-white rounded-2xl p-5" style={{ border: '1px solid #EDE8FF' }}>
            <h3 className="font-bold text-navy text-sm mb-1">Répartition sévérités</h3>
            <p className="text-xs mb-3" style={{ color: '#6B6B8A' }}>Toutes vulnérabilités</p>
            {dashLoading ? (
              <div className="h-44 flex items-center justify-center">
                <Loader size={22} className="animate-spin" style={{ color: '#7C6FF7' }} />
              </div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height={140}>
                  <PieChart>
                    <Pie data={stats?.severityDistribution ?? []} cx="50%" cy="50%"
                         innerRadius={40} outerRadius={65} paddingAngle={3}
                         dataKey="value" nameKey="name">
                      {(stats?.severityDistribution ?? []).map((entry) => (
                        <Cell key={entry.name} fill={SEV_COLORS[entry.name] ?? '#6B6B8A'} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ border: '1px solid #EDE8FF', borderRadius: 8, fontSize: 12 }}
                      formatter={(val, name) => [val, SEV_LABELS[name as string] ?? name]}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex flex-wrap gap-2 mt-1 justify-center">
                  {Object.entries(SEV_COLORS).map(([sev, color]) => {
                    const entry = stats?.severityDistribution?.find(d => d.name === sev);
                    return (
                      <div key={sev} className="flex items-center gap-1 text-[11px]">
                        <span className="w-2 h-2 rounded-full inline-block" style={{ background: color }} />
                        <span style={{ color: '#6B6B8A' }}>{SEV_LABELS[sev]}</span>
                        <span className="font-mono font-bold text-navy">{entry?.value ?? 0}</span>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </div>
        </div>

        {/* ── Bottom row ─────────────────────────────────────────────── */}
        <div className="grid grid-cols-3 gap-5">

          {/* Scans récents */}
          <div className="col-span-2 bg-white rounded-2xl overflow-hidden" style={{ border: '1px solid #EDE8FF' }}>
            <div className="px-6 py-4 flex items-center justify-between" style={{ borderBottom: '1px solid #EDE8FF' }}>
              <div>
                <h3 className="font-bold text-navy text-sm">Scans récents</h3>
                <p className="text-xs mt-0.5" style={{ color: '#6B6B8A' }}>5 derniers — cliquez pour voir</p>
              </div>
              <button onClick={() => navigate('/scans')}
                      className="flex items-center gap-1 text-xs font-semibold"
                      style={{ color: '#7C6FF7' }}>
                Voir tous <ChevronRight size={14} />
              </button>
            </div>

            {/* Header */}
            <div className="grid px-6 py-2.5 text-[10px] font-bold uppercase tracking-wider"
                 style={{ gridTemplateColumns: '2fr 1fr 1.5fr auto', background: '#FAFAFA', borderBottom: '1px solid #EDE8FF', color: '#6B6B8A' }}>
              <div>URL Cible</div>
              <div>Statut</div>
              <div>Date</div>
              <div />
            </div>

            {scansLoading ? (
              <div className="py-10 flex justify-center">
                <Loader size={22} className="animate-spin" style={{ color: '#7C6FF7' }} />
              </div>
            ) : scans.length === 0 ? (
              <div className="py-12 text-center">
                <Search size={24} className="mx-auto mb-3" style={{ color: '#EDE8FF' }} />
                <p className="text-sm font-medium text-navy">Aucun scan pour l'instant</p>
                <button onClick={() => navigate('/scans/new')}
                        className="mt-3 px-4 py-2 rounded-xl text-sm font-semibold text-white"
                        style={{ background: '#FF6B6B' }}>
                  Lancer un scan
                </button>
              </div>
            ) : (
              scans.map(scan => (
                <div key={scan.id}
                     className="grid px-6 py-3.5 cursor-pointer group transition-all"
                     style={{ gridTemplateColumns: '2fr 1fr 1.5fr auto', borderBottom: '1px solid #F8F6FF' }}
                     onClick={() => navigate(scan.status === 'COMPLETED' || scan.status === 'FAILED'
                       ? `/scans/${scan.id}/results` : `/scans/${scan.id}/live`)}
                     onMouseEnter={e => (e.currentTarget.style.background = '#FAFAFE')}
                     onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                  <div className="min-w-0 flex items-center">
                    <div>
                      <p className="font-mono text-sm font-semibold text-navy truncate">
                        {scan.targetUrl.replace(/^https?:\/\//, '')}
                      </p>
                      <p className="text-[11px] mt-0.5" style={{ color: '#6B6B8A' }}>
                        {scan.depth} · {scan.threads} threads
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center">{statusPill(scan.status)}</div>
                  <div className="flex items-center text-xs" style={{ color: '#6B6B8A' }}>
                    {timeAgo(scan.createdAt)}
                  </div>
                  <div className="flex items-center gap-2">
                    <button className="opacity-0 group-hover:opacity-100 transition-all p-1 rounded"
                            style={{ color: '#7C6FF7' }} title="Voir"
                            onClick={e => { e.stopPropagation(); navigate(`/scans/${scan.id}/results`); }}>
                      <Eye size={14} />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Module insights */}
          <div className="bg-white rounded-2xl p-5 space-y-3" style={{ border: '1px solid #EDE8FF' }}>
            <div>
              <h3 className="font-bold text-navy text-sm">Top Modules</h3>
              <p className="text-xs" style={{ color: '#6B6B8A' }}>Par taux de détection</p>
            </div>
            {dashLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader size={18} className="animate-spin" style={{ color: '#7C6FF7' }} />
              </div>
            ) : (stats?.moduleInsights ?? []).length === 0 ? (
              <p className="text-xs" style={{ color: '#6B6B8A' }}>Aucune donnée disponible</p>
            ) : (
              <div className="space-y-2">
                {(stats?.moduleInsights ?? []).slice(0, 7).map((m, i) => (
                  <div key={m.name}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <span className="font-mono text-[10px] text-navy font-bold min-w-[16px]">#{i + 1}</span>
                        <span className="text-xs text-navy truncate">{m.name}</span>
                      </div>
                      <span className="font-mono text-xs font-bold shrink-0 ml-2"
                            style={{ color: m.detectionRate >= 80 ? '#4ECDC4' : m.detectionRate >= 50 ? '#FFB347' : '#FF6B6B' }}>
                        {m.detectionRate}%
                      </span>
                    </div>
                    <div className="w-full rounded-full h-1.5" style={{ background: '#F0EEFF' }}>
                      <div className="h-1.5 rounded-full transition-all duration-700"
                           style={{ width: `${m.detectionRate}%`, background: m.detectionRate >= 80 ? '#4ECDC4' : m.detectionRate >= 50 ? '#FFB347' : '#FF6B6B' }} />
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Bar chart pour catégories */}
            {(stats?.moduleInsights ?? []).length > 0 && (
              <div className="pt-2" style={{ borderTop: '1px solid #F0EEFF' }}>
                <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: '#6B6B8A' }}>
                  Temps moyen par module
                </p>
                <ResponsiveContainer width="100%" height={80}>
                  <BarChart data={(stats?.moduleInsights ?? []).slice(0, 5)} margin={{ top: 0, right: 0, bottom: 0, left: -30 }}>
                    <XAxis dataKey="name" tick={{ fontSize: 8, fill: '#6B6B8A' }} tickLine={false}
                           tickFormatter={n => n.split(' ')[0]} />
                    <YAxis tick={{ fontSize: 8, fill: '#6B6B8A' }} tickLine={false} axisLine={false} unit="ms" />
                    <Tooltip
                      contentStyle={{ border: '1px solid #EDE8FF', borderRadius: 8, fontSize: 11 }}
                      formatter={(v) => [`${v}ms`, 'Temps moyen']}
                    />
                    <Bar dataKey="avgTime" fill="#7C6FF7" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
}
