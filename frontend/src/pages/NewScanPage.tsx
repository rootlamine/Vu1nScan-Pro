import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowLeft, Shield, ChevronDown, ChevronUp, Play,
  BookmarkIcon, AlertTriangle, CheckCircle2, Clock, Search,
} from 'lucide-react';
import { Layout } from '@/components/ui/Layout';
import api from '@/services/api';
import type { ScanModule, ModuleCategory } from '@/types';

/* ── URL / IP validation ──────────────────────────────────────────── */
const IP_RE = /^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$/;

const schema = z.object({
  targetUrl: z.string().refine(val => {
    const v = val.trim();
    if (!v) return false;
    if (IP_RE.test(v)) return true;
    try { new URL(v.startsWith('http') ? v : `http://${v}`); return true; } catch { return false; }
  }, { message: 'URL (https://exemple.com) ou adresse IP (192.168.1.1) invalide' }),
  description: z.string().max(500).optional(),
  depth:       z.enum(['fast', 'normal', 'deep']).default('normal'),
  threads:     z.coerce.number().min(1).max(10).default(5),
});
type FormData = z.infer<typeof schema>;

/* ── Severity config ──────────────────────────────────────────────── */
const SEV_CFG: Record<string, { label: string; bg: string; color: string }> = {
  CRITICAL: { label: 'CRITIQUE', bg: '#FFF0F0', color: '#FF6B6B' },
  HIGH:     { label: 'HAUTE',    bg: '#FFF7E6', color: '#FFB347' },
  MEDIUM:   { label: 'MOYENNE',  bg: '#F0EEFF', color: '#7C6FF7' },
  LOW:      { label: 'FAIBLE',   bg: '#E8FFFE', color: '#4ECDC4' },
};

/* ── Module metadata (icon + severity + CVSS) ─────────────────────── */
const MODULE_META: Record<string, { severity: string; cvss: number; icon: string }> = {
  sql_injection:            { severity: 'CRITICAL', cvss: 9.8, icon: '≡'   },
  xss_scanner:              { severity: 'HIGH',     cvss: 7.2, icon: '<>'  },
  port_scanner:             { severity: 'HIGH',     cvss: 9.1, icon: '⋮'   },
  http_headers:             { severity: 'MEDIUM',   cvss: 7.5, icon: 'HDR' },
  ssl_checker:              { severity: 'MEDIUM',   cvss: 5.3, icon: '🔒'  },
  csrf_scanner:             { severity: 'MEDIUM',   cvss: 6.5, icon: '↺'   },
  directory_traversal:      { severity: 'HIGH',     cvss: 7.5, icon: '../' },
  open_redirect:            { severity: 'MEDIUM',   cvss: 6.1, icon: '→'   },
  security_misconfiguration:{ severity: 'HIGH',     cvss: 7.2, icon: '⚙'   },
  sensitive_files:          { severity: 'MEDIUM',   cvss: 5.8, icon: 'TXT' },
  whois_lookup:             { severity: 'LOW',      cvss: 2.0, icon: 'W'   },
  dns_recon:                { severity: 'HIGH',     cvss: 9.1, icon: 'DNS' },
  subdomain_enum:           { severity: 'MEDIUM',   cvss: 4.3, icon: '.*'  },
  email_harvester:          { severity: 'LOW',      cvss: 3.1, icon: '@'   },
  technology_fingerprint:   { severity: 'LOW',      cvss: 2.5, icon: 'FP'  },
  google_dorks:             { severity: 'HIGH',     cvss: 7.0, icon: 'G'   },
  metadata_extractor:       { severity: 'MEDIUM',   cvss: 4.5, icon: 'M'   },
  broken_links:             { severity: 'LOW',      cvss: 2.5, icon: '404' },
  javascript_analyzer:      { severity: 'CRITICAL', cvss: 9.0, icon: 'JS'  },
};

/* ── Category tabs ────────────────────────────────────────────────── */
type CatTab = 'ALL' | ModuleCategory;

const CAT_TABS: { key: CatTab; label: string; color: string }[] = [
  { key: 'ALL',      label: 'Tous',     color: '#6B6B8A' },
  { key: 'SECURITY', label: 'Sécurité', color: '#FF6B6B' },
  { key: 'NETWORK',  label: 'Réseau',   color: '#4ECDC4' },
  { key: 'OSINT',    label: 'OSINT',    color: '#7C6FF7' },
  { key: 'SCRAPING', label: 'Scraping', color: '#FFB347' },
];

const CAT_BG: Record<string, { bg: string; color: string }> = {
  SECURITY: { bg: '#FFF0F0', color: '#FF6B6B' },
  NETWORK:  { bg: '#E8FFFE', color: '#4ECDC4' },
  OSINT:    { bg: '#F0EEFF', color: '#7C6FF7' },
  SCRAPING: { bg: '#FFF7E6', color: '#FFB347' },
};

/* ── Recommended slugs ────────────────────────────────────────────── */
const RECOMMENDED = [
  'sql_injection', 'xss_scanner', 'http_headers', 'ssl_checker',
  'csrf_scanner', 'port_scanner', 'technology_fingerprint', 'javascript_analyzer',
];

const DEPTH_OPTS = [
  { value: 'fast',   label: 'Rapide (~5 min)'       },
  { value: 'normal', label: 'Normal (~15 min)'       },
  { value: 'deep',   label: 'Approfondi (~45 min)'   },
] as const;

const THREAD_OPTS = [
  { value: '1',  label: '1 thread (prudent)' },
  { value: '3',  label: '3 threads'          },
  { value: '5',  label: '5 threads'          },
  { value: '10', label: '10 threads (rapide)'},
] as const;

/* ── Page ─────────────────────────────────────────────────────────── */
export default function NewScanPage() {
  const navigate = useNavigate();
  const [submitError,     setSubmitError]     = useState('');
  const [selectedModules, setSelectedModules] = useState<Set<string>>(new Set());
  const [optionsOpen,     setOptionsOpen]     = useState(false);
  const [urlValue,        setUrlValue]        = useState('');
  const [catFilter,       setCatFilter]       = useState<CatTab>('ALL');
  const [search,          setSearch]          = useState('');

  const { data: modulesData } = useQuery<{ data: { data: ScanModule[] } }>({
    queryKey: ['modules'],
    queryFn:  () => api.get('/modules'),
  });
  const modules = modulesData?.data?.data ?? [];

  useEffect(() => {
    if (modules.length > 0 && selectedModules.size === 0) {
      setSelectedModules(new Set(modules.filter(m => m.defaultEnabled && m.isActive).map(m => m.id)));
    }
  }, [modules]);

  const { register, handleSubmit, watch, setValue, formState: { errors, isSubmitting } } =
    useForm<FormData>({
      resolver: zodResolver(schema),
      defaultValues: { depth: 'normal', threads: 5 },
    });

  const depth   = watch('depth');
  const threads = watch('threads');

  const toggleModule = (id: string) => {
    setSelectedModules(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const selectAll         = () => setSelectedModules(new Set(visibleModules.map(m => m.id)));
  const deselectAll       = () => setSelectedModules(new Set());
  const selectRecommended = () => {
    const ids = modules.filter(m => RECOMMENDED.includes(m.slug)).map(m => m.id);
    setSelectedModules(new Set(ids));
  };

  const onSubmit = async (data: FormData) => {
    setSubmitError('');
    const url = IP_RE.test(data.targetUrl.trim())
      ? `http://${data.targetUrl.trim()}`
      : data.targetUrl.trim();
    try {
      const res = await api.post('/scans', { ...data, targetUrl: url, threads: Number(data.threads) });
      navigate(`/scans/${res.data.data.id}/live`);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })
        ?.response?.data?.message ?? 'Erreur lors du lancement';
      setSubmitError(msg);
    }
  };

  // Filter visible modules
  const visibleModules = modules.filter(m => {
    const matchCat = catFilter === 'ALL' || m.category === catFilter;
    const matchSearch = !search || m.name.toLowerCase().includes(search.toLowerCase()) ||
      m.description.toLowerCase().includes(search.toLowerCase());
    return matchCat && matchSearch;
  });

  const urlDomain = urlValue.replace(/^https?:\/\//, '').replace(/\/.*$/, '') || '—';
  const selectedModuleNames = modules.filter(m => selectedModules.has(m.id)).map(m => m.name.split(' ')[0]);

  const DEPTH_LABEL: Record<string, string> = { fast: 'Rapide', normal: 'Normal', deep: 'Approfondi' };
  const estimatedTime = { fast: '~5 minutes', normal: '~20 minutes', deep: '~45 minutes' }[depth] ?? '~20 minutes';

  const isValidUrl = urlValue.trim() && !errors.targetUrl;

  return (
    <Layout>
      {/* Topbar */}
      <div className="flex items-center justify-between px-8 py-4 bg-white"
           style={{ borderBottom: '1px solid #EDE8FF' }}>
        <div className="flex items-center gap-3">
          <button onClick={() => navigate(-1)}
                  className="flex items-center gap-1 text-sm font-medium transition-all"
                  style={{ color: '#6B6B8A' }}>
            <ArrowLeft size={15} /> Retour
          </button>
          <span style={{ color: '#EDE8FF' }}>|</span>
          <h1 className="font-bold text-navy text-base">Nouveau scan</h1>
        </div>
        <div className="text-xs" style={{ color: '#6B6B8A' }}>Scans &gt; Nouveau</div>
      </div>

      <div className="flex gap-6 px-8 py-6">
        {/* ── Formulaire principal ──────────────────────────────── */}
        <div className="flex-1 min-w-0 space-y-5">
          {submitError && (
            <div className="rounded-xl p-4 text-sm"
                 style={{ background: '#FFF0F0', color: '#FF6B6B', border: '1px solid #FFD0D0' }}>
              {submitError}
            </div>
          )}

          {/* Cible du scan */}
          <div className="bg-white rounded-2xl p-6" style={{ border: '1px solid #EDE8FF' }}>
            <div className="flex items-center gap-2 mb-4">
              <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: '#F0EEFF' }}>
                <Shield size={14} className="text-violet" />
              </div>
              <div>
                <p className="font-bold text-navy text-sm">Cible du scan</p>
                <p className="text-xs" style={{ color: '#6B6B8A' }}>URL complète ou adresse IP du système à analyser</p>
              </div>
            </div>

            {/* URL / IP input */}
            <div className="flex items-stretch rounded-xl overflow-hidden mb-3"
                 style={{ border: errors.targetUrl ? '1.5px solid #FF6B6B' : '1.5px solid #EDE8FF' }}>
              <input
                {...register('targetUrl', {
                  onChange: e => { setUrlValue(e.target.value); },
                })}
                placeholder="https://exemple.com  ou  192.168.1.1:8080"
                className="flex-1 px-4 py-3 font-mono text-sm outline-none bg-white text-navy"
              />
              {urlValue && (
                <div className="flex items-center pr-3 gap-1.5 shrink-0">
                  <CheckCircle2 size={14} style={{ color: errors.targetUrl ? '#FF6B6B' : '#4ECDC4' }} />
                  <span className="text-xs font-semibold"
                        style={{ color: errors.targetUrl ? '#FF6B6B' : '#4ECDC4' }}>
                    {errors.targetUrl ? 'Invalide' : 'Valide'}
                  </span>
                </div>
              )}
            </div>
            {errors.targetUrl && (
              <p className="text-xs mb-3" style={{ color: '#FF6B6B' }}>{errors.targetUrl.message}</p>
            )}

            <textarea
              {...register('description')}
              placeholder="Audit de sécurité — description optionnelle"
              rows={2}
              className="w-full px-4 py-3 rounded-xl text-sm outline-none resize-none"
              style={{ border: '1.5px solid #EDE8FF', background: '#FAFAFA' }}
            />
          </div>

          {/* Modules de détection */}
          <div className="bg-white rounded-2xl p-6" style={{ border: '1px solid #EDE8FF' }}>
            {/* Header */}
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: '#FFF0F0' }}>
                  <Shield size={14} style={{ color: '#FF6B6B' }} />
                </div>
                <div>
                  <p className="font-bold text-navy text-sm">Modules de détection</p>
                  <p className="text-xs" style={{ color: '#6B6B8A' }}>Choisissez les analyses à effectuer</p>
                </div>
              </div>
              <span className="font-mono text-xs font-bold px-2.5 py-1 rounded-full"
                    style={{ background: '#F0EEFF', color: '#7C6FF7' }}>
                {selectedModules.size}/{modules.length} sélectionnés
              </span>
            </div>

            {/* Search + category tabs */}
            <div className="flex items-center gap-3 mb-4 flex-wrap">
              {/* Search */}
              <div className="relative flex-1 min-w-[180px]">
                <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder="Filtrer les modules…"
                  className="w-full pl-8 pr-3 py-2 rounded-xl text-xs outline-none"
                  style={{ border: '1px solid #EDE8FF', background: '#FAFAFA' }}
                />
              </div>
              {/* Category tabs */}
              <div className="flex gap-1 flex-wrap">
                {CAT_TABS.map(t => (
                  <button
                    key={t.key}
                    type="button"
                    onClick={() => setCatFilter(t.key)}
                    className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all"
                    style={catFilter === t.key
                      ? { background: t.color, color: '#fff' }
                      : { background: '#F8F8F8', color: '#6B6B8A', border: '1px solid #EDE8FF' }
                    }
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Quick select buttons */}
            <div className="flex gap-2 mb-4">
              <button type="button" onClick={selectAll}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
                      style={{ border: '1px solid #EDE8FF', color: '#6B6B8A', background: '#FAFAFA' }}>
                Tout sélectionner
              </button>
              <button type="button" onClick={selectRecommended}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all"
                      style={{ background: '#F0EEFF', color: '#7C6FF7' }}>
                ★ Sélection recommandée
              </button>
              <button type="button" onClick={deselectAll}
                      className="px-3 py-1.5 rounded-lg text-xs font-medium transition-all"
                      style={{ border: '1px solid #EDE8FF', color: '#6B6B8A', background: '#FAFAFA' }}>
                Tout désélectionner
              </button>
            </div>

            {/* Module list */}
            {visibleModules.length === 0 ? (
              <p className="text-sm text-center py-6" style={{ color: '#6B6B8A' }}>
                Aucun module pour ces filtres
              </p>
            ) : (
              <div className="space-y-0">
                {visibleModules.map((m, i) => {
                  const meta     = MODULE_META[m.slug];
                  const sev      = meta ? SEV_CFG[meta.severity] : SEV_CFG.MEDIUM;
                  const catStyle = CAT_BG[m.category] ?? CAT_BG.SECURITY;
                  const selected = selectedModules.has(m.id);
                  return (
                    <div
                      key={m.id}
                      className="py-4 cursor-pointer transition-all"
                      style={{ borderBottom: i < visibleModules.length - 1 ? '1px solid #F8F6FF' : 'none' }}
                      onClick={() => toggleModule(m.id)}
                    >
                      <div className="flex items-start gap-3">
                        {/* Icon */}
                        <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 font-mono text-xs font-bold"
                             style={{ background: sev.bg, color: sev.color }}>
                          {meta?.icon ?? '⚡'}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="font-bold text-navy text-sm">{m.name}</p>
                            {/* Category badge */}
                            <span className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wide"
                                  style={{ background: catStyle.bg, color: catStyle.color }}>
                              {m.category}
                            </span>
                          </div>
                          <p className="text-xs mt-0.5 leading-relaxed" style={{ color: '#6B6B8A' }}>
                            {m.description}
                          </p>
                          {meta && (
                            <span className="inline-flex items-center gap-1 mt-1.5 text-[10px] font-bold px-2 py-0.5 rounded-full"
                                  style={{ background: sev.bg, color: sev.color }}>
                              {sev.label} · CVSS {meta.cvss.toFixed(1)}
                            </span>
                          )}
                        </div>
                        {/* Checkbox */}
                        <div className="shrink-0 mt-0.5">
                          <div className="w-5 h-5 rounded flex items-center justify-center transition-all"
                               style={{
                                 background: selected ? '#7C6FF7' : 'transparent',
                                 border: selected ? '1.5px solid #7C6FF7' : '1.5px solid #EDE8FF',
                               }}>
                            {selected && <CheckCircle2 size={12} color="#fff" />}
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Options avancées */}
          <div className="bg-white rounded-2xl overflow-hidden" style={{ border: '1px solid #EDE8FF' }}>
            <button
              type="button"
              className="w-full flex items-center justify-between px-6 py-4"
              onClick={() => setOptionsOpen(!optionsOpen)}
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs px-1.5 rounded" style={{ background: '#F0EEFF', color: '#7C6FF7' }}>
                  {'{·}'}
                </span>
                <span className="font-semibold text-navy text-sm">Options avancées</span>
              </div>
              {optionsOpen
                ? <ChevronUp size={16} style={{ color: '#6B6B8A' }} />
                : <ChevronDown size={16} style={{ color: '#6B6B8A' }} />}
            </button>
            {optionsOpen && (
              <div className="px-6 pb-6 grid grid-cols-2 gap-4" style={{ borderTop: '1px solid #EDE8FF' }}>
                <div className="pt-4">
                  <label className="block text-xs font-bold text-navy mb-2 uppercase tracking-wide">
                    Profondeur d'analyse
                  </label>
                  <select {...register('depth')} className="w-full px-3 py-2.5 rounded-xl text-sm outline-none"
                          style={{ border: '1.5px solid #EDE8FF', background: '#FAFAFA' }}>
                    {DEPTH_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
                <div className="pt-4">
                  <label className="block text-xs font-bold text-navy mb-2 uppercase tracking-wide">
                    Threads parallèles
                  </label>
                  <select {...register('threads')} className="w-full px-3 py-2.5 rounded-xl text-sm outline-none"
                          style={{ border: '1.5px solid #EDE8FF', background: '#FAFAFA' }}>
                    {THREAD_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ── Sidebar résumé (sticky) ───────────────────────────── */}
        <div className="w-[280px] shrink-0">
          <div className="sticky top-6 space-y-4">
            <div className="bg-white rounded-2xl p-5" style={{ border: '1px solid #EDE8FF' }}>
              <h3 className="font-bold text-navy text-sm mb-0.5">Résumé du scan</h3>
              <p className="text-xs mb-5" style={{ color: '#6B6B8A' }}>Prêt à lancer l'analyse</p>

              <div className="mb-4">
                <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: '#6B6B8A' }}>
                  URL Cible
                </p>
                <p className="font-mono text-sm text-navy truncate">{urlDomain}</p>
              </div>

              <div className="mb-4">
                <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: '#6B6B8A' }}>
                  Modules sélectionnés ({selectedModules.size})
                </p>
                <div className="flex flex-wrap gap-1">
                  {selectedModuleNames.slice(0, 4).map(name => (
                    <span key={name} className="text-[10px] px-2 py-0.5 rounded-full font-medium"
                          style={{ background: '#F0EEFF', color: '#7C6FF7' }}>
                      {name}
                    </span>
                  ))}
                  {selectedModuleNames.length > 4 && (
                    <span className="text-[10px] px-2 py-0.5 rounded-full font-medium"
                          style={{ background: '#F0EEFF', color: '#7C6FF7' }}>
                      +{selectedModuleNames.length - 4}
                    </span>
                  )}
                </div>
              </div>

              <div className="mb-5">
                <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: '#6B6B8A' }}>
                  Configuration
                </p>
                <div className="flex items-center gap-1.5 text-xs" style={{ color: '#6B6B8A' }}>
                  <Clock size={12} />
                  {DEPTH_LABEL[depth] ?? 'Normal'} · {threads || 5} thread{(threads || 5) > 1 ? 's' : ''}
                </div>
              </div>

              <div className="mb-5 rounded-xl p-3" style={{ background: '#F8F6FF' }}>
                <p className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: '#6B6B8A' }}>
                  Durée estimée
                </p>
                <p className="font-bold text-navy text-sm">{estimatedTime}</p>
              </div>

              <button
                onClick={handleSubmit(onSubmit)}
                disabled={isSubmitting}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl font-bold text-sm text-white mb-2 transition-all disabled:opacity-50"
                style={{ background: '#FF6B6B' }}
              >
                <Play size={15} />
                {isSubmitting ? 'Lancement…' : 'Lancer le scan'}
              </button>
              <button
                type="button"
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl font-medium text-sm transition-all"
                style={{ border: '1px solid #EDE8FF', color: '#6B6B8A' }}
              >
                <BookmarkIcon size={13} />
                Sauvegarder en brouillon
              </button>
            </div>

            <div className="rounded-xl p-4" style={{ background: '#FFF7E6', border: '1px solid #FFB347' }}>
              <div className="flex items-start gap-2">
                <AlertTriangle size={14} style={{ color: '#FFB347' }} className="shrink-0 mt-0.5" />
                <p className="text-xs leading-relaxed" style={{ color: '#664D00' }}>
                  Scannez uniquement des systèmes dont vous avez explicitement l'autorisation écrite.
                  Toute utilisation non autorisée est illégale.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
