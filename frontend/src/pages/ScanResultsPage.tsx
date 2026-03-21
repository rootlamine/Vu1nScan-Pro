import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft, Download, Search, ChevronDown, ChevronUp,
  CheckCircle2, AlertTriangle, RefreshCw, ChevronLeft, ChevronRight, ExternalLink,
  FileJson, FileText, Ban, MessageSquare, ShieldCheck,
} from 'lucide-react';
import { Layout } from '@/components/ui/Layout';
import { Toast }  from '@/components/ui/Toast';
import api from '@/services/api';
import type { Vulnerability, VulnStats } from '@/types';

type SeverityFilter = '' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
type SortOption     = 'cvss_desc' | 'cvss_asc' | 'name_asc';

const PAGE_SIZE = 20;

const SEV: Record<string, { label: string; bg: string; color: string; border: string }> = {
  CRITICAL: { label: 'CRITIQUE', bg: '#FFF0F0', color: '#FF6B6B', border: '#FF6B6B' },
  HIGH:     { label: 'HAUTE',    bg: '#FFF7E6', color: '#FFB347', border: '#FFB347' },
  MEDIUM:   { label: 'MOYENNE',  bg: '#F0EEFF', color: '#7C6FF7', border: '#7C6FF7' },
  LOW:      { label: 'FAIBLE',   bg: '#E8FFFE', color: '#4ECDC4', border: '#4ECDC4' },
};

/* ── Vuln card accordion ──────────────────────────────────────────── */
function VulnCard({ vuln, open, onToggle, onUpdated }: {
  vuln: Vulnerability; open: boolean; onToggle: () => void;
  onUpdated: (id: string, data: Partial<Vulnerability>) => void;
}) {
  const c = SEV[vuln.severity] ?? SEV.LOW;
  const [localNotes, setLocalNotes] = useState(vuln.notes ?? '');
  const [notesDirty, setNotesDirty] = useState(false);
  const queryClient = useQueryClient();

  const { mutate: updateVuln } = useMutation({
    mutationFn: (data: { isResolved?: boolean; isFalsePositive?: boolean; notes?: string }) =>
      api.patch(`/vulnerabilities/${vuln.id}`, data),
    onSuccess: (res: { data: { data: Vulnerability } }) => {
      onUpdated(vuln.id, res.data.data);
      queryClient.invalidateQueries({ queryKey: ['vulns'] });
      setNotesDirty(false);
    },
  });

  return (
    <div className="bg-white rounded-2xl overflow-hidden transition-all"
         style={{
           border: open ? `1.5px solid ${c.border}` : '1px solid #EDE8FF',
           opacity: vuln.isFalsePositive ? 0.6 : 1,
         }}>
      <button
        className="w-full flex items-center gap-4 px-5 py-4 text-left transition-all"
        style={{ background: open ? `${c.bg}60` : 'transparent' }}
        onClick={onToggle}
      >
        <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-black shrink-0"
              style={{ background: c.bg, color: c.color }}>
          {c.label}
        </span>
        <div className="flex-1 min-w-0">
          <p className="font-bold text-navy text-sm flex items-center gap-2">
            {vuln.name}
            {vuln.isResolved && (
              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full"
                    style={{ background: '#dcfce7', color: '#16a34a' }}>Résolu</span>
            )}
            {vuln.isFalsePositive && (
              <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded-full"
                    style={{ background: '#f3f4f6', color: '#6b7280' }}>Faux positif</span>
            )}
          </p>
          {vuln.endpoint && (
            <p className="font-mono text-xs mt-0.5 truncate" style={{ color: '#6B6B8A' }}>
              {vuln.endpoint}
            </p>
          )}
        </div>
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
          <div className="flex items-center gap-2 flex-wrap pt-3">
            {vuln.cveId && (
              <span className="text-xs font-mono px-2.5 py-0.5 rounded-full font-semibold"
                    style={{ background: '#F0EEFF', color: '#7C6FF7', border: '1px solid #EDE8FF' }}>
                🔗 {vuln.cveId}
              </span>
            )}
            {vuln.cweId && (
              <span className="text-xs font-mono px-2.5 py-0.5 rounded-full font-semibold"
                    style={{ background: '#F0EEFF', color: '#7C6FF7', border: '1px solid #EDE8FF' }}>
                {vuln.cweId}
              </span>
            )}
            {vuln.cvssVector && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded"
                    style={{ background: '#1C1C2E', color: '#4ECDC4' }}>
                {vuln.cvssVector}
              </span>
            )}
            {vuln.parameter && (
              <span className="text-xs font-mono px-2.5 py-0.5 rounded-full"
                    style={{ background: '#EDE8FF', color: '#6B6B8A' }}>
                ≡ Paramètre: {vuln.parameter}
              </span>
            )}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: '#6B6B8A' }}>
                ⓘ Description
              </p>
              <p className="text-sm leading-relaxed" style={{ color: '#6B6B8A' }}>{vuln.description}</p>
              {vuln.impact && (
                <div className="mt-3 rounded-xl p-3" style={{ background: '#FFF7ED', borderLeft: '3px solid #FFB347' }}>
                  <p className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: '#B45309' }}>Impact</p>
                  <p className="text-xs" style={{ color: '#374151' }}>{vuln.impact}</p>
                </div>
              )}
            </div>
            <div className="space-y-3">
              {vuln.payload && (
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: '#6B6B8A' }}>
                    Payload utilisé
                  </p>
                  <pre className="rounded-xl px-4 py-3 text-xs font-mono overflow-x-auto leading-relaxed"
                       style={{ background: '#1C1C2E', color: '#A8FFD8' }}>
                    {vuln.payload}
                  </pre>
                </div>
              )}
              {vuln.evidence && (
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: '#6B6B8A' }}>
                    Preuve
                  </p>
                  <code className="block text-xs rounded-xl px-4 py-3 break-all"
                        style={{ background: '#f0fdf4', color: '#065f46' }}>
                    {vuln.evidence}
                  </code>
                </div>
              )}
            </div>
          </div>

          <div className="rounded-xl p-4" style={{ background: '#E8FFFE', borderLeft: '3px solid #4ECDC4' }}>
            <p className="text-xs font-bold mb-2 flex items-center gap-1.5 uppercase tracking-wide"
               style={{ color: '#2A9D8F' }}>
              <CheckCircle2 size={13} /> Recommandation de remédiation
            </p>
            <p className="text-sm leading-relaxed" style={{ color: '#1C1C2E' }}>{vuln.recommendation}</p>
          </div>

          {vuln.references && vuln.references.length > 0 && (
            <div className="rounded-xl p-4" style={{ background: '#F0EEFF', borderLeft: '3px solid #7C6FF7' }}>
              <p className="text-xs font-bold mb-3 uppercase tracking-wide" style={{ color: '#7C6FF7' }}>
                Pour aller plus loin
              </p>
              <ul className="space-y-1.5">
                {vuln.references.map(ref => (
                  <li key={ref}>
                    <a href={ref} target="_blank" rel="noopener noreferrer"
                       className="flex items-center gap-1.5 text-xs font-medium"
                       style={{ color: '#7C6FF7' }}>
                      <ExternalLink size={11} style={{ flexShrink: 0 }} />
                      {ref}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* ── Actions ── */}
          <div className="flex items-center gap-2 flex-wrap pt-1" style={{ borderTop: '1px solid #F0EEFF' }}>
            <button
              onClick={() => updateVuln({ isResolved: !vuln.isResolved })}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all"
              style={vuln.isResolved
                ? { background: '#dcfce7', color: '#16a34a', border: '1px solid #bbf7d0' }
                : { background: '#f0fdf4', color: '#16a34a', border: '1px solid #dcfce7' }}>
              <ShieldCheck size={12} />
              {vuln.isResolved ? 'Résolu ✓' : 'Marquer résolu'}
            </button>
            <button
              onClick={() => updateVuln({ isFalsePositive: !vuln.isFalsePositive })}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all"
              style={vuln.isFalsePositive
                ? { background: '#f3f4f6', color: '#6b7280', border: '1px solid #e5e7eb' }
                : { background: '#fafafa', color: '#6b7280', border: '1px solid #e5e7eb' }}>
              <Ban size={12} />
              {vuln.isFalsePositive ? 'Faux positif ✓' : 'Faux positif'}
            </button>
          </div>

          {/* Notes */}
          <div>
            <label className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider mb-1.5"
                   style={{ color: '#6B6B8A' }}>
              <MessageSquare size={11} /> Notes
            </label>
            <div className="relative">
              <textarea
                value={localNotes}
                onChange={e => { setLocalNotes(e.target.value); setNotesDirty(true); }}
                placeholder="Ajouter une note sur cette vulnérabilité..."
                rows={2}
                className="w-full text-sm rounded-xl px-3 py-2 outline-none resize-none"
                style={{ border: '1px solid #EDE8FF', background: '#FAFAFA', color: '#1C1C2E' }}
              />
              {notesDirty && (
                <button
                  onClick={() => updateVuln({ notes: localNotes })}
                  className="absolute bottom-2 right-2 px-2.5 py-1 rounded-lg text-[10px] font-semibold text-white"
                  style={{ background: '#7C6FF7' }}>
                  Sauvegarder
                </button>
              )}
            </div>
            {vuln.notes && !notesDirty && (
              <p className="text-xs mt-1" style={{ color: '#6B6B8A' }}>Note : {vuln.notes}</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Risk score ──────────────────────────────────────────────────── */
function calcRiskScore(stats: VulnStats | undefined): number {
  if (!stats) return 0;
  const raw = stats.critical * 10 + stats.high * 7 + stats.medium * 4 + stats.low * 1;
  const max = stats.total * 10;
  return max > 0 ? Math.min(100, Math.round((raw / max) * 100)) : 0;
}

/* ── Page ─────────────────────────────────────────────────────────── */
export default function ScanResultsPage() {
  const { id }      = useParams<{ id: string }>();
  const navigate    = useNavigate();
  const queryClient = useQueryClient();

  const [sevFilter, setSevFilter] = useState<SeverityFilter>('');
  const [search,    setSearch]    = useState('');
  const [sort,      setSort]      = useState<SortOption>('cvss_desc');
  const [openVuln,  setOpenVuln]  = useState<string | null>(null);
  const [page,      setPage]      = useState(1);
  const [toast, setToast]         = useState<{ msg: string; type: 'success' | 'error' } | null>(null);
  // Local vuln overrides (for immediate UI update after mutation)
  const [vulnOverrides, setVulnOverrides] = useState<Record<string, Partial<Vulnerability>>>({});

  const handleVulnUpdated = (id: string, data: Partial<Vulnerability>) => {
    setVulnOverrides(prev => ({ ...prev, [id]: { ...(prev[id] ?? {}), ...data } }));
  };

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
  let allVulns = vulnsData?.data?.data ?? [];

  // Client-side sort
  if (sort === 'cvss_desc') allVulns = [...allVulns].sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
  if (sort === 'cvss_asc')  allVulns = [...allVulns].sort((a, b) => (a.cvssScore ?? 0) - (b.cvssScore ?? 0));
  if (sort === 'name_asc')  allVulns = [...allVulns].sort((a, b) => a.name.localeCompare(b.name));

  // Pagination
  const totalPages = Math.max(1, Math.ceil(allVulns.length / PAGE_SIZE));
  const vulns      = allVulns.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const changePage = (p: number) => {
    setPage(p);
    setOpenVuln(null);
  };

  // Reset to page 1 when filters change
  const handleSevFilter = (v: SeverityFilter) => { setSevFilter(v); setPage(1); setOpenVuln(null); };
  const handleSearch    = (v: string)           => { setSearch(v);   setPage(1); };
  const handleSort      = (v: SortOption)        => { setSort(v);    setPage(1); };

  const { mutate: generatePDF, isPending: generating } = useMutation({
    mutationFn: () => api.post(`/scans/${id}/report`, {}),
    onSuccess:  () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      setToast({ msg: 'Rapport PDF généré ! Disponible dans Rapports.', type: 'success' });
    },
    onError: () => setToast({ msg: 'Erreur lors de la génération', type: 'error' }),
  });

  const handleExportJSON = () => window.open(`/api/scans/${id}/export/json`, '_blank');
  const handleExportCSV  = () => window.open(`/api/scans/${id}/export/csv`,  '_blank');

  const riskScore = calcRiskScore(stats);
  const riskColor = riskScore >= 80 ? '#FF6B6B' : riskScore >= 60 ? '#FFB347' : riskScore >= 40 ? '#7C6FF7' : '#4ECDC4';
  const riskLabel = riskScore >= 80 ? 'CRITIQUE' : riskScore >= 60 ? 'ÉLEVÉ' : riskScore >= 40 ? 'MOYEN' : riskScore > 0 ? 'FAIBLE' : 'MINIMAL';

  const totalVulns = (stats?.critical ?? 0) + (stats?.high ?? 0) + (stats?.medium ?? 0) + (stats?.low ?? 0);

  const FILTER_TABS = [
    { v: '' as SeverityFilter,         label: `Toutes (${totalVulns})` },
    { v: 'CRITICAL' as SeverityFilter, label: `Critiques (${stats?.critical ?? 0})` },
    { v: 'HIGH' as SeverityFilter,     label: `Hautes (${stats?.high ?? 0})` },
    { v: 'MEDIUM' as SeverityFilter,   label: `Moyennes (${stats?.medium ?? 0})` },
    { v: 'LOW' as SeverityFilter,      label: `Faibles (${stats?.low ?? 0})` },
  ];

  let duration = '';
  if (scan?.startedAt && scan?.completedAt) {
    const ms  = new Date(scan.completedAt).getTime() - new Date(scan.startedAt).getTime();
    const min = Math.floor(ms / 60000);
    const sec = Math.floor((ms % 60000) / 1000);
    duration = `${min} min ${sec} sec`;
  }
  const moduleCount = (scan?.moduleResults as unknown[] | undefined)?.length ?? 0;

  return (
    <Layout>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}

      {/* Top bar */}
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
          <button onClick={handleExportJSON}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm font-medium transition-all"
                  style={{ border: '1px solid #EDE8FF', color: '#7C6FF7' }}>
            <FileJson size={14} /> JSON
          </button>
          <button onClick={handleExportCSV}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm font-medium transition-all"
                  style={{ border: '1px solid #EDE8FF', color: '#4ECDC4' }}>
            <FileText size={14} /> CSV
          </button>
          <button
            onClick={() => generatePDF()}
            disabled={generating}
            className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-semibold text-white transition-all disabled:opacity-50"
            style={{ background: '#7C6FF7' }}
          >
            <Download size={14} />
            {generating ? 'Génération…' : 'Rapport PDF'}
          </button>
        </div>
      </div>

      <div className="px-8 py-6 space-y-5">
        {/* Bannière scan */}
        <div className="bg-white rounded-2xl p-5" style={{ border: '1px solid #EDE8FF' }}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
                   style={{ background: '#E8FFFE' }}>
                <CheckCircle2 size={20} style={{ color: '#4ECDC4' }} />
              </div>
              <div>
                <p className="font-mono font-bold text-navy text-base">{scan?.targetUrl ?? '…'}</p>
                <div className="flex items-center gap-3 mt-1 text-xs" style={{ color: '#6B6B8A' }}>
                  {scan?.startedAt && (
                    <span>📅 {new Date(scan.startedAt).toLocaleDateString('fr-FR', {
                      day: 'numeric', month: 'long', year: 'numeric',
                      hour: '2-digit', minute: '2-digit',
                    })}</span>
                  )}
                  {duration && <span>⏱ {duration}</span>}
                  {moduleCount > 0 && <span>⚙ {moduleCount} modules</span>}
                  <span className="font-semibold" style={{ color: '#4ECDC4' }}>✓ COMPLETED</span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-4">
              {/* Risk score */}
              {stats && stats.total > 0 && (
                <div className="text-center px-4 py-2 rounded-xl"
                     style={{ background: `${riskColor}15`, border: `1px solid ${riskColor}30` }}>
                  <p className="font-mono font-black text-2xl" style={{ color: riskColor }}>{riskScore}</p>
                  <p className="text-[9px] font-bold uppercase tracking-wide" style={{ color: riskColor }}>
                    Risque {riskLabel}
                  </p>
                </div>
              )}
              {/* Severity counts */}
              {[
                { key: 'critical', count: stats?.critical ?? 0, color: '#FF6B6B', label: 'CRITIQUE' },
                { key: 'high',     count: stats?.high     ?? 0, color: '#FFB347', label: 'HAUTE'    },
                { key: 'medium',   count: stats?.medium   ?? 0, color: '#7C6FF7', label: 'MOYENNE'  },
                { key: 'low',      count: stats?.low      ?? 0, color: '#4ECDC4', label: 'FAIBLE'   },
              ].map(s => (
                <div key={s.key} className="text-center">
                  <p className="font-mono font-black text-xl" style={{ color: s.color }}>{s.count}</p>
                  <p className="text-[9px] font-bold uppercase tracking-wide" style={{ color: s.color }}>{s.label}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Filtres */}
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative" style={{ minWidth: 220 }}>
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
            <input
              value={search}
              onChange={e => handleSearch(e.target.value)}
              placeholder="Rechercher une vulnérabilité, un end..."
              className="w-full pl-9 pr-4 py-2.5 rounded-xl text-sm outline-none"
              style={{ border: '1px solid #EDE8FF', background: '#fff' }}
            />
          </div>

          <div className="flex gap-1 flex-wrap">
            {FILTER_TABS.map(f => (
              <button
                key={f.v}
                onClick={() => handleSevFilter(f.v)}
                className="px-3.5 py-2 rounded-xl text-sm font-semibold transition-all"
                style={sevFilter === f.v
                  ? { background: '#1C1C2E', color: '#fff' }
                  : { background: '#fff', color: '#6B6B8A', border: '1px solid #EDE8FF' }
                }
              >
                {f.label}
              </button>
            ))}
          </div>

          <select
            value={sort}
            onChange={e => handleSort(e.target.value as SortOption)}
            className="ml-auto px-3 py-2.5 rounded-xl text-sm outline-none"
            style={{ border: '1px solid #EDE8FF', background: '#fff', color: '#6B6B8A' }}
          >
            <option value="cvss_desc">CVSS décroissant</option>
            <option value="cvss_asc">CVSS croissant</option>
            <option value="name_asc">Nom A→Z</option>
          </select>
        </div>

        {/* Vulnérabilités */}
        {isLoading ? (
          <div className="text-center py-12" style={{ color: '#6B6B8A' }}>Chargement…</div>
        ) : allVulns.length === 0 ? (
          <div className="bg-white rounded-2xl py-14 text-center" style={{ border: '1px solid #EDE8FF' }}>
            <AlertTriangle size={28} className="mx-auto mb-3" style={{ color: '#EDE8FF' }} />
            <p className="font-medium text-navy">
              {sevFilter || search ? 'Aucun résultat pour ces filtres' : 'Aucune vulnérabilité détectée'}
            </p>
          </div>
        ) : (
          <>
            {/* Results count */}
            <div className="flex items-center justify-between text-xs" style={{ color: '#6B6B8A' }}>
              <span>
                {allVulns.length} vulnérabilité{allVulns.length > 1 ? 's' : ''}
                {totalPages > 1 && ` — page ${page}/${totalPages}`}
              </span>
              {totalPages > 1 && (
                <span>{(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, allVulns.length)} affichées</span>
              )}
            </div>

            <div className="space-y-3">
              {vulns.map(vuln => (
                <VulnCard
                  key={vuln.id}
                  vuln={{ ...vuln, ...(vulnOverrides[vuln.id] ?? {}) }}
                  open={openVuln === vuln.id}
                  onToggle={() => setOpenVuln(openVuln === vuln.id ? null : vuln.id)}
                  onUpdated={handleVulnUpdated}
                />
              ))}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between mt-4">
                <span className="text-sm" style={{ color: '#6B6B8A' }}>
                  Page {page} sur {totalPages}
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => changePage(Math.max(1, page - 1))}
                    disabled={page === 1}
                    className="w-9 h-9 rounded-xl flex items-center justify-center transition-all disabled:opacity-40"
                    style={{ border: '1px solid #EDE8FF', color: '#6B6B8A' }}
                  >
                    <ChevronLeft size={16} />
                  </button>
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    const p = page <= 3 ? i + 1
                      : page >= totalPages - 2 ? totalPages - 4 + i
                      : page - 2 + i;
                    if (p < 1 || p > totalPages) return null;
                    return (
                      <button
                        key={p}
                        onClick={() => changePage(p)}
                        className="w-9 h-9 rounded-xl flex items-center justify-center text-sm font-semibold transition-all"
                        style={p === page
                          ? { background: '#1C1C2E', color: '#fff' }
                          : { border: '1px solid #EDE8FF', color: '#6B6B8A' }
                        }
                      >
                        {p}
                      </button>
                    );
                  })}
                  <button
                    onClick={() => changePage(Math.min(totalPages, page + 1))}
                    disabled={page === totalPages}
                    className="w-9 h-9 rounded-xl flex items-center justify-center transition-all disabled:opacity-40"
                    style={{ border: '1px solid #EDE8FF', color: '#6B6B8A' }}
                  >
                    <ChevronRight size={16} />
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </Layout>
  );
}
