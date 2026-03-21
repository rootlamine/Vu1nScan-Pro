import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft, Download, Search, ChevronDown, ChevronUp,
  CheckCircle2, AlertTriangle, RefreshCw, Code2,
} from 'lucide-react';
import { Layout } from '@/components/ui/Layout';
import { Toast }  from '@/components/ui/Toast';
import api from '@/services/api';
import type { Vulnerability, VulnStats } from '@/types';

type SeverityFilter = '' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
type SortOption = 'cvss_desc' | 'cvss_asc' | 'name_asc';

const SEV: Record<string, { label: string; bg: string; color: string; border: string }> = {
  CRITICAL: { label: 'CRITIQUE', bg: '#FFF0F0', color: '#FF6B6B', border: '#FF6B6B' },
  HIGH:     { label: 'HAUTE',    bg: '#FFF7E6', color: '#FFB347', border: '#FFB347' },
  MEDIUM:   { label: 'MOYENNE',  bg: '#F0EEFF', color: '#7C6FF7', border: '#7C6FF7' },
  LOW:      { label: 'FAIBLE',   bg: '#E8FFFE', color: '#4ECDC4', border: '#4ECDC4' },
};

/* ── Vuln card accordion ──────────────────────────────────────────── */
function VulnCard({ vuln, open, onToggle }: {
  vuln: Vulnerability; open: boolean; onToggle: () => void;
}) {
  const c = SEV[vuln.severity] ?? SEV.LOW;
  return (
    <div className="bg-white rounded-2xl overflow-hidden transition-all"
         style={{ border: open ? `1.5px solid ${c.border}` : '1px solid #EDE8FF' }}>
      <button
        className="w-full flex items-center gap-4 px-5 py-4 text-left transition-all"
        style={{ background: open ? `${c.bg}60` : 'transparent' }}
        onClick={onToggle}
      >
        {/* Severity pill */}
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-black shrink-0"
              style={{ background: c.bg, color: c.color }}>
          {c.label}
        </span>
        {/* Name + endpoint */}
        <div className="flex-1 min-w-0">
          <p className="font-bold text-navy text-sm">{vuln.name}</p>
          {vuln.endpoint && (
            <p className="font-mono text-xs mt-0.5 truncate" style={{ color: '#6B6B8A' }}>
              {vuln.endpoint}
            </p>
          )}
        </div>
        {/* CVSS score */}
        {vuln.cvssScore != null && (
          <span className="font-mono text-sm font-black shrink-0 px-2 py-0.5 rounded"
                style={{ background: c.bg, color: c.color }}>
            {vuln.cvssScore.toFixed(1)}
          </span>
        )}
        <span style={{ color: '#6B6B8A' }}>
          {open ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </span>
      </button>

      {open && (
        <div className="px-5 pb-5 space-y-4" style={{ borderTop: `1px solid ${c.border}30` }}>
          {/* Tags */}
          <div className="flex items-center gap-2 flex-wrap pt-3">
            {vuln.cveId && (
              <span className="text-xs font-mono px-2.5 py-0.5 rounded-full font-semibold"
                    style={{ background: '#F0EEFF', color: '#7C6FF7', border: '1px solid #EDE8FF' }}>
                🔗 {vuln.cveId}
              </span>
            )}
            {vuln.parameter && (
              <span className="text-xs font-mono px-2.5 py-0.5 rounded-full"
                    style={{ background: '#EDE8FF', color: '#6B6B8A' }}>
                ≡ Paramètre: {vuln.parameter}
              </span>
            )}
          </div>

          {/* Description + Payload */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider mb-2 flex items-center gap-1"
                 style={{ color: '#6B6B8A' }}>
                ⓘ Description
              </p>
              <p className="text-sm leading-relaxed" style={{ color: '#6B6B8A' }}>
                {vuln.description}
              </p>
            </div>
            {vuln.payload && (
              <div>
                <p className="text-[10px] font-bold uppercase tracking-wider mb-2 flex items-center gap-1"
                   style={{ color: '#6B6B8A' }}>
                  &lt;&gt; Payload utilisé
                </p>
                <pre className="rounded-xl px-4 py-3 text-xs font-mono overflow-x-auto leading-relaxed relative"
                     style={{ background: '#1C1C2E', color: '#A8FFD8', minHeight: 80 }}>
                  <span className="absolute top-2 right-3 text-[10px] uppercase tracking-wider opacity-40"
                        style={{ color: '#A8FFD8' }}>
                    PAYLOAD
                  </span>
                  {vuln.payload}
                </pre>
              </div>
            )}
          </div>

          {/* Recommandation */}
          <div className="rounded-xl p-4" style={{ background: '#E8FFFE', borderLeft: '3px solid #4ECDC4' }}>
            <p className="text-xs font-bold mb-2 flex items-center gap-1.5 uppercase tracking-wide"
               style={{ color: '#2A9D8F' }}>
              <CheckCircle2 size={13} /> Recommandation de remédiation
            </p>
            <p className="text-sm leading-relaxed" style={{ color: '#1C1C2E' }}>
              {vuln.recommendation}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Page ─────────────────────────────────────────────────────────── */
export default function ScanResultsPage() {
  const { id }      = useParams<{ id: string }>();
  const navigate    = useNavigate();
  const queryClient = useQueryClient();

  const [sevFilter,  setSevFilter]  = useState<SeverityFilter>('');
  const [search,     setSearch]     = useState('');
  const [sort,       setSort]       = useState<SortOption>('cvss_desc');
  const [openVuln,   setOpenVuln]   = useState<string | null>(null);
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null);

  const { data: scanData } = useQuery<{ data: { data: { targetUrl: string; status: string; startedAt: string; completedAt: string; moduleResults?: unknown[] } } }>({
    queryKey: ['scan', id],
    queryFn:  () => api.get(`/scans/${id}`),
  });
  const scan = scanData?.data?.data;

  const { data: statsData } = useQuery<{ data: { data: VulnStats } }>({
    queryKey: ['scan-stats', id],
    queryFn:  () => api.get(`/scans/${id}/stats`),
  });
  const stats = statsData?.data?.data;

  const params = new URLSearchParams();
  if (sevFilter) params.set('severity', sevFilter);
  if (search)    params.set('search',   search);

  const { data: vulnsData, isLoading } = useQuery<{ data: { data: Vulnerability[] } }>({
    queryKey: ['vulns', id, sevFilter, search, sort],
    queryFn:  () => api.get(`/scans/${id}/vulnerabilities?${params}`),
  });
  let vulns = vulnsData?.data?.data ?? [];

  // Client-side sort
  if (sort === 'cvss_desc') vulns = [...vulns].sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
  if (sort === 'cvss_asc')  vulns = [...vulns].sort((a, b) => (a.cvssScore ?? 0) - (b.cvssScore ?? 0));
  if (sort === 'name_asc')  vulns = [...vulns].sort((a, b) => a.name.localeCompare(b.name));

  const { mutate: generatePDF, isPending: generating } = useMutation({
    mutationFn: () => api.post(`/scans/${id}/report`, {}),
    onSuccess:  () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      setToast({ msg: 'Rapport PDF généré ! Disponible dans Rapports.', type: 'success' });
    },
    onError: () => setToast({ msg: 'Erreur lors de la génération', type: 'error' }),
  });

  const totalVulns = (stats?.critical ?? 0) + (stats?.high ?? 0) + (stats?.medium ?? 0) + (stats?.low ?? 0);

  const FILTER_TABS = [
    { v: '' as SeverityFilter,         label: `Toutes (${totalVulns})` },
    { v: 'CRITICAL' as SeverityFilter, label: `Critiques (${stats?.critical ?? 0})` },
    { v: 'HIGH' as SeverityFilter,     label: `Hautes (${stats?.high ?? 0})` },
    { v: 'MEDIUM' as SeverityFilter,   label: `Moyennes (${stats?.medium ?? 0})` },
    { v: 'LOW' as SeverityFilter,      label: `Faibles (${stats?.low ?? 0})` },
  ];

  // Scan duration
  let duration = '';
  if (scan?.startedAt && scan?.completedAt) {
    const ms = new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime();
    const min = Math.floor(ms / 60000);
    const sec = Math.floor((ms % 60000) / 1000);
    duration = `${min} min ${sec} sec`;
  }

  const moduleCount = (scan?.moduleResults as unknown[] | undefined)?.length ?? 0;

  return (
    <Layout>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

      {/* ── Top bar ──────────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-8 py-4 bg-white"
           style={{ borderBottom: '1px solid #EDE8FF' }}>
        <div className="flex items-center gap-3">
          <button onClick={() => navigate('/scans')}
                  className="flex items-center gap-1 text-sm font-medium"
                  style={{ color: '#6B6B8A' }}>
            <ArrowLeft size={15} /> Mes scans
          </button>
          <span style={{ color: '#EDE8FF' }}>|</span>
          <h1 className="font-bold text-navy text-base">Résultats du scan</h1>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => navigate(`/scans/${id}/live`)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm font-medium transition-all"
            style={{ border: '1px solid #EDE8FF', color: '#6B6B8A' }}
          >
            <RefreshCw size={14} /> Relancer
          </button>
          <button
            onClick={() => generatePDF()}
            disabled={generating}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-semibold text-white transition-all disabled:opacity-50"
            style={{ background: '#7C6FF7' }}
          >
            <Download size={14} />
            {generating ? 'Génération…' : 'Exporter PDF'}
          </button>
        </div>
      </div>

      <div className="px-8 py-6 space-y-5">
        {/* ── Bannière scan ────────────────────────────────────────── */}
        <div className="bg-white rounded-2xl p-5" style={{ border: '1px solid #EDE8FF' }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                   style={{ background: '#E8FFFE' }}>
                <CheckCircle2 size={20} style={{ color: '#4ECDC4' }} />
              </div>
              <div>
                <p className="font-mono font-bold text-navy text-base">
                  {scan?.targetUrl ?? '…'}
                </p>
                <div className="flex items-center gap-3 mt-1 text-xs" style={{ color: '#6B6B8A' }}>
                  {scan?.startedAt && (
                    <span>
                      📅 {new Date(scan.startedAt).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' })}
                    </span>
                  )}
                  {duration && <span>⏱ {duration}</span>}
                  {moduleCount > 0 && <span>⚙ {moduleCount} modules</span>}
                  <span className="font-semibold" style={{ color: '#4ECDC4' }}>✓ COMPLETED</span>
                </div>
              </div>
            </div>

            {/* Severity counts */}
            <div className="flex items-center gap-3">
              {[
                { key: 'critical', count: stats?.critical ?? 0, color: '#FF6B6B', label: 'CRITIQUE' },
                { key: 'high',     count: stats?.high     ?? 0, color: '#FFB347', label: 'HAUTE'    },
                { key: 'medium',   count: stats?.medium   ?? 0, color: '#7C6FF7', label: 'MOYENNE'  },
                { key: 'low',      count: stats?.low      ?? 0, color: '#4ECDC4', label: 'FAIBLE'   },
              ].map(s => (
                <div key={s.key} className="text-center">
                  <p className="font-mono font-black text-xl" style={{ color: s.color }}>
                    {s.count}
                  </p>
                  <p className="text-[9px] font-bold uppercase tracking-wide" style={{ color: s.color }}>
                    {s.label}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Filtres ──────────────────────────────────────────────── */}
        <div className="flex items-center gap-3 flex-wrap">
          {/* Search */}
          <div className="relative" style={{ minWidth: 220 }}>
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Rechercher une vulnérabilité, un end..."
              className="w-full pl-9 pr-4 py-2.5 rounded-xl text-sm outline-none"
              style={{ border: '1px solid #EDE8FF', background: '#fff' }}
            />
          </div>

          {/* Tab filters */}
          <div className="flex gap-1 flex-wrap">
            {FILTER_TABS.map(f => (
              <button
                key={f.v}
                onClick={() => setSevFilter(f.v)}
                className="px-3.5 py-2 rounded-xl text-sm font-semibold transition-all"
                style={
                  sevFilter === f.v
                    ? { background: '#1C1C2E', color: '#fff' }
                    : { background: '#fff', color: '#6B6B8A', border: '1px solid #EDE8FF' }
                }
              >
                {f.label}
              </button>
            ))}
          </div>

          {/* Sort */}
          <select
            value={sort}
            onChange={e => setSort(e.target.value as SortOption)}
            className="ml-auto px-3 py-2.5 rounded-xl text-sm outline-none"
            style={{ border: '1px solid #EDE8FF', background: '#fff', color: '#6B6B8A' }}
          >
            <option value="cvss_desc">CVSS décroissant</option>
            <option value="cvss_asc">CVSS croissant</option>
            <option value="name_asc">Nom A→Z</option>
          </select>
        </div>

        {/* ── Vulnérabilités ───────────────────────────────────────── */}
        {isLoading ? (
          <div className="text-center py-12" style={{ color: '#6B6B8A' }}>Chargement…</div>
        ) : vulns.length === 0 ? (
          <div className="bg-white rounded-2xl py-14 text-center" style={{ border: '1px solid #EDE8FF' }}>
            <AlertTriangle size={28} className="mx-auto mb-3" style={{ color: '#EDE8FF' }} />
            <p className="font-medium text-navy">
              {sevFilter || search ? 'Aucun résultat pour ces filtres' : 'Aucune vulnérabilité détectée'}
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {vulns.map(vuln => (
              <VulnCard
                key={vuln.id}
                vuln={vuln}
                open={openVuln === vuln.id}
                onToggle={() => setOpenVuln(openVuln === vuln.id ? null : vuln.id)}
              />
            ))}
          </div>
        )}
      </div>
    </Layout>
  );
}
