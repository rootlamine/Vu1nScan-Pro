import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft, Shield, ChevronDown, ChevronUp, Play,
  BookmarkIcon, AlertTriangle, CheckCircle2, Clock, Search,
  Bookmark, X, ChevronDown as ChevDown,
} from 'lucide-react';
import { Layout } from '@/components/ui/Layout';
import api from '@/services/api';
import type { ScanModule, ModuleCategory, ScanProfile, MyLimitsResp } from '@/types';

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

const saveProfileSchema = z.object({
  profileName: z.string().min(1, 'Nom requis').max(100),
  profileDesc: z.string().max(500).optional(),
});
type SaveProfileForm = z.infer<typeof saveProfileSchema>;

/* ── Severity config ──────────────────────────────────────────────── */
const SEV_CFG: Record<string, { label: string; bg: string; color: string }> = {
  CRITICAL: { label: 'CRITIQUE', bg: '#FFF0F0', color: '#FF6B6B' },
  HIGH:     { label: 'HAUTE',    bg: '#FFF7E6', color: '#FFB347' },
  MEDIUM:   { label: 'MOYENNE',  bg: '#F0EEFF', color: '#7C6FF7' },
  LOW:      { label: 'FAIBLE',   bg: '#E8FFFE', color: '#4ECDC4' },
};

/* ── Module metadata (icon + severity + CVSS) ─────────────────────── */
const MODULE_META: Record<string, { severity: string; cvss: number; icon: string }> = {
  // Existing
  sql_injection:            { severity: 'CRITICAL', cvss: 9.8, icon: '≡'    },
  xss_scanner:              { severity: 'HIGH',     cvss: 7.2, icon: '<>'   },
  port_scanner:             { severity: 'HIGH',     cvss: 9.1, icon: '⋮'    },
  http_headers:             { severity: 'MEDIUM',   cvss: 7.5, icon: 'HDR'  },
  ssl_checker:              { severity: 'MEDIUM',   cvss: 5.3, icon: '🔒'   },
  csrf_scanner:             { severity: 'MEDIUM',   cvss: 6.5, icon: '↺'    },
  directory_traversal:      { severity: 'HIGH',     cvss: 7.5, icon: '../'  },
  open_redirect:            { severity: 'MEDIUM',   cvss: 6.1, icon: '→'    },
  security_misconfiguration:{ severity: 'HIGH',     cvss: 7.2, icon: '⚙'    },
  sensitive_files:          { severity: 'MEDIUM',   cvss: 5.8, icon: 'TXT'  },
  whois_lookup:             { severity: 'LOW',      cvss: 2.0, icon: 'W'    },
  dns_recon:                { severity: 'HIGH',     cvss: 9.1, icon: 'DNS'  },
  subdomain_enum:           { severity: 'MEDIUM',   cvss: 4.3, icon: '.*'   },
  email_harvester:          { severity: 'LOW',      cvss: 3.1, icon: '@'    },
  technology_fingerprint:   { severity: 'LOW',      cvss: 2.5, icon: 'FP'   },
  google_dorks:             { severity: 'HIGH',     cvss: 7.0, icon: 'G'    },
  metadata_extractor:       { severity: 'MEDIUM',   cvss: 4.5, icon: 'M'    },
  broken_links:             { severity: 'LOW',      cvss: 2.5, icon: '404'  },
  javascript_analyzer:      { severity: 'CRITICAL', cvss: 9.0, icon: 'JS'   },
  // New offensive modules
  lfi_rfi_scanner:          { severity: 'CRITICAL', cvss: 9.0, icon: '../'  },
  xxe_scanner:              { severity: 'HIGH',     cvss: 8.2, icon: 'XXE'  },
  ssrf_scanner:             { severity: 'HIGH',     cvss: 8.6, icon: 'SSRF' },
  command_injection:        { severity: 'CRITICAL', cvss: 9.8, icon: '>_'   },
  http_methods_scanner:     { severity: 'MEDIUM',   cvss: 6.5, icon: 'PUT'  },
  api_fuzzer:               { severity: 'HIGH',     cvss: 8.0, icon: '/v1'  },
  broken_auth_api:          { severity: 'HIGH',     cvss: 8.8, icon: 'JWT'  },
  graphql_introspection:    { severity: 'MEDIUM',   cvss: 5.3, icon: 'GQL'  },
  rate_limit_tester:        { severity: 'MEDIUM',   cvss: 5.3, icon: '⏱'   },
  banner_grabbing:          { severity: 'MEDIUM',   cvss: 5.0, icon: 'BNR'  },
  firewall_detection:       { severity: 'MEDIUM',   cvss: 4.0, icon: '🔥'   },
  traceroute_analysis:      { severity: 'LOW',      cvss: 3.0, icon: 'HOP'  },
  ipv6_scanner:             { severity: 'MEDIUM',   cvss: 4.5, icon: 'v6'   },
  os_fingerprint:           { severity: 'LOW',      cvss: 3.7, icon: 'OS'   },
  service_version_scan:     { severity: 'HIGH',     cvss: 7.5, icon: 'CVE'  },
  default_credentials:      { severity: 'CRITICAL', cvss: 9.8, icon: 'PWD'  },
};

/* ── Category tabs ────────────────────────────────────────────────── */
type CatTab = 'ALL' | ModuleCategory;

const CAT_TABS: { key: CatTab; label: string; color: string }[] = [
  { key: 'ALL',              label: 'Tous',           color: '#6B6B8A' },
  { key: 'SECURITY',         label: 'Sécurité',       color: '#FF6B6B' },
  { key: 'WEB_OFFENSIVE',    label: 'Web Offensif',   color: '#E05252' },
  { key: 'API_OFFENSIVE',    label: 'API Offensif',   color: '#C0392B' },
  { key: 'NETWORK',          label: 'Réseau',         color: '#4ECDC4' },
  { key: 'NETWORK_OFFENSIVE',label: 'Réseau Offensif',color: '#2E86AB' },
  { key: 'OSINT',            label: 'OSINT',          color: '#7C6FF7' },
  { key: 'SCRAPING',         label: 'Scraping',       color: '#FFB347' },
  { key: 'SYSTEM',           label: 'Système',        color: '#8E44AD' },
];

const CAT_BG: Record<string, { bg: string; color: string }> = {
  SECURITY:          { bg: '#FFF0F0', color: '#FF6B6B' },
  NETWORK:           { bg: '#E8FFFE', color: '#4ECDC4' },
  OSINT:             { bg: '#F0EEFF', color: '#7C6FF7' },
  SCRAPING:          { bg: '#FFF7E6', color: '#FFB347' },
  WEB_OFFENSIVE:     { bg: '#FFE8E8', color: '#E05252' },
  API_OFFENSIVE:     { bg: '#FFE0E0', color: '#C0392B' },
  NETWORK_OFFENSIVE: { bg: '#E0F0FF', color: '#2E86AB' },
  SYSTEM:            { bg: '#F5E6FF', color: '#8E44AD' },
};

/* ── Recommended slugs ────────────────────────────────────────────── */
const RECOMMENDED = [
  'sql_injection', 'xss_scanner', 'http_headers', 'ssl_checker',
  'csrf_scanner', 'port_scanner', 'technology_fingerprint', 'javascript_analyzer',
];

/* ── Reconnaissance profile slugs (default) ──────────────────────── */
const RECON_SLUGS = [
  'whois_lookup', 'dns_recon', 'subdomain_enum',
  'email_harvester', 'technology_fingerprint',
  'http_headers', 'port_scanner',
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
  const navigate     = useNavigate();
  const queryClient  = useQueryClient();
  const [submitError,       setSubmitError]       = useState('');
  const [selectedModules,   setSelectedModules]   = useState<Set<string>>(new Set());
  const [optionsOpen,       setOptionsOpen]       = useState(false);
  const [urlValue,          setUrlValue]          = useState('');
  const [catFilter,         setCatFilter]         = useState<CatTab>('ALL');
  const [search,            setSearch]            = useState('');
  const [selectedProfileId, setSelectedProfileId] = useState<string>('');
  const [showSaveModal,     setShowSaveModal]     = useState(false);
  const [saveError,         setSaveError]         = useState('');

  /* ── Queries ─────────────────────────────────────────────────────── */
  const { data: modulesData } = useQuery<{ data: { data: ScanModule[] } }>({
    queryKey: ['modules'],
    queryFn:  () => api.get('/modules'),
  });
  const modules = modulesData?.data?.data ?? [];

  const { data: profilesData } = useQuery<{ data: { data: ScanProfile[] } }>({
    queryKey: ['profiles'],
    queryFn:  () => api.get('/profiles'),
  });
  const profiles = profilesData?.data?.data ?? [];

  const { data: limitsData } = useQuery<{ data: { data: MyLimitsResp } }>({
    queryKey: ['my-limits'],
    queryFn:  () => api.get('/auth/me/limits'),
  });
  const limits = limitsData?.data?.data;

  /* ── Profile save mutation ───────────────────────────────────────── */
  const saveMutation = useMutation({
    mutationFn: (data: { name: string; description?: string; modules: string[] }) =>
      api.post('/profiles', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['profiles'] });
      setShowSaveModal(false);
      profileForm.reset();
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { message?: string } } })
        ?.response?.data?.message ?? 'Erreur lors de la sauvegarde';
      setSaveError(msg);
    },
  });

  /* ── Default module selection ─────────────────────────────────────── */
  useEffect(() => {
    if (modules.length > 0 && selectedModules.size === 0) {
      setSelectedModules(new Set(modules.filter(m => m.defaultEnabled && m.isActive).map(m => m.id)));
    }
  }, [modules]);

  /* ── Main form ────────────────────────────────────────────────────── */
  const { register, handleSubmit, watch, formState: { errors, isSubmitting } } =
    useForm<FormData>({
      resolver: zodResolver(schema),
      defaultValues: { depth: 'normal', threads: 5 },
    });

  /* ── Profile save form ────────────────────────────────────────────── */
  const profileForm = useForm<SaveProfileForm>({
    resolver: zodResolver(saveProfileSchema),
  });

  const depth   = watch('depth');
  const threads = watch('threads');

  /* ── Toggles ─────────────────────────────────────────────────────── */
  const toggleModule = (id: string) => {
    setSelectedModules(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
    setSelectedProfileId(''); // clear profile when user manually changes
  };

  const selectAll         = () => { setSelectedModules(new Set(visibleModules.map(m => m.id))); setSelectedProfileId(''); };
  const deselectAll       = () => { setSelectedModules(new Set()); setSelectedProfileId(''); };
  const selectRecommended = () => {
    const ids = modules.filter(m => RECOMMENDED.includes(m.slug)).map(m => m.id);
    setSelectedModules(new Set(ids));
    setSelectedProfileId('');
  };

  /* ── Apply profile ────────────────────────────────────────────────── */
  const applyProfile = (profileId: string) => {
    setSelectedProfileId(profileId);
    if (!profileId) return;
    const profile = profiles.find(p => p.id === profileId);
    if (!profile) return;
    const ids = modules.filter(m => profile.modules.includes(m.slug)).map(m => m.id);
    setSelectedModules(new Set(ids));
  };

  /* ── Submit ──────────────────────────────────────────────────────── */
  const onSubmit = async (data: FormData) => {
    setSubmitError('');
    const url = IP_RE.test(data.targetUrl.trim())
      ? `http://${data.targetUrl.trim()}`
      : data.targetUrl.trim();

    let moduleIds = Array.from(selectedModules);

    // Default: if no modules selected, apply Reconnaissance
    if (moduleIds.length === 0) {
      const reconIds = modules.filter(m => RECON_SLUGS.includes(m.slug)).map(m => m.id);
      moduleIds = reconIds;
    }

    try {
      const res = await api.post('/scans', {
        ...data,
        targetUrl: url,
        threads: Number(data.threads),
        moduleIds,
      });
      navigate(`/scans/${res.data.data.id}/live`);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })
        ?.response?.data?.message ?? 'Erreur lors du lancement';
      setSubmitError(msg);
    }
  };

  /* ── Save profile ────────────────────────────────────────────────── */
  const onSaveProfile = (data: SaveProfileForm) => {
    setSaveError('');
    const slugs = modules.filter(m => selectedModules.has(m.id)).map(m => m.slug);
    if (slugs.length === 0) {
      setSaveError('Aucun module sélectionné');
      return;
    }
    saveMutation.mutate({
      name:        data.profileName,
      description: data.profileDesc,
      modules:     slugs,
    });
  };

  // Filter visible modules
  const visibleModules = modules.filter(m => {
    const matchCat    = catFilter === 'ALL' || m.category === catFilter;
    const matchSearch = !search || m.name.toLowerCase().includes(search.toLowerCase()) ||
      m.description.toLowerCase().includes(search.toLowerCase());
    return matchCat && matchSearch;
  });

  const urlDomain = urlValue.replace(/^https?:\/\//, '').replace(/\/.*$/, '') || '—';
  const selectedModuleNames = modules.filter(m => selectedModules.has(m.id)).map(m => m.name.split(' ')[0]);

  const DEPTH_LABEL: Record<string, string> = { fast: 'Rapide', normal: 'Normal', deep: 'Approfondi' };
  const estimatedTime = { fast: '~5 minutes', normal: '~20 minutes', deep: '~45 minutes' }[depth] ?? '~20 minutes';

  const noModulesSelected = selectedModules.size === 0;

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
                {...register('targetUrl', { onChange: e => setUrlValue(e.target.value) })}
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

          {/* ── Profil de scan ─────────────────────────────────── */}
          <div className="bg-white rounded-2xl p-6" style={{ border: '1px solid #EDE8FF' }}>
            <div className="flex items-center gap-2 mb-4">
              <div className="w-7 h-7 rounded-lg flex items-center justify-center" style={{ background: '#FFF7E6' }}>
                <Bookmark size={14} style={{ color: '#FFB347' }} />
              </div>
              <div>
                <p className="font-bold text-navy text-sm">Profil de scan</p>
                <p className="text-xs" style={{ color: '#6B6B8A' }}>Appliquer un profil pour pré-sélectionner les modules</p>
              </div>
            </div>

            <div className="flex gap-3 flex-wrap">
              {/* Profile dropdown */}
              <div className="relative flex-1 min-w-[200px]">
                <select
                  value={selectedProfileId}
                  onChange={e => applyProfile(e.target.value)}
                  className="w-full px-4 py-2.5 rounded-xl text-sm outline-none appearance-none pr-8"
                  style={{ border: '1.5px solid #EDE8FF', background: '#FAFAFA', color: selectedProfileId ? '#1C1C2E' : '#6B6B8A' }}
                >
                  <option value="">— Choisir un profil —</option>
                  {profiles.map(p => (
                    <option key={p.id} value={p.id}>
                      {p.name}{p.isDefault ? ' (défaut)' : ''}
                    </option>
                  ))}
                </select>
                <ChevDown size={14} className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none"
                          style={{ color: '#6B6B8A' }} />
              </div>

              {/* Save as profile button */}
              <button
                type="button"
                onClick={() => { setShowSaveModal(true); setSaveError(''); profileForm.reset(); }}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all shrink-0"
                style={{ border: '1.5px solid #7C6FF7', color: '#7C6FF7', background: '#F0EEFF' }}
              >
                <BookmarkIcon size={13} />
                Sauvegarder comme profil
              </button>
            </div>

            {selectedProfileId && (
              <div className="mt-3 flex items-center gap-2">
                <div className="w-2 h-2 rounded-full" style={{ background: '#FFB347' }} />
                <p className="text-xs" style={{ color: '#6B6B8A' }}>
                  Profil appliqué : <strong style={{ color: '#1C1C2E' }}>
                    {profiles.find(p => p.id === selectedProfileId)?.name}
                  </strong> — {selectedModules.size} module(s) sélectionné(s)
                </p>
              </div>
            )}

            {/* Default profile notice */}
            {noModulesSelected && (
              <div className="mt-3 flex items-start gap-2 rounded-xl p-3" style={{ background: '#FFF7E6', border: '1px solid #FFE4A0' }}>
                <AlertTriangle size={13} style={{ color: '#FFB347', flexShrink: 0, marginTop: 1 }} />
                <p className="text-xs" style={{ color: '#664D00' }}>
                  Aucun module sélectionné. Le profil <strong>Reconnaissance</strong> sera appliqué par défaut
                  (WHOIS, DNS, sous-domaines, emails, fingerprinting, headers, ports).
                </p>
              </div>
            )}
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
            <div className="flex gap-2 mb-4 flex-wrap">
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
                        <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 font-mono text-xs font-bold"
                             style={{ background: sev.bg, color: sev.color }}>
                          {meta?.icon ?? '⚡'}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="font-bold text-navy text-sm">{m.name}</p>
                            <span className="text-[9px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wide"
                                  style={{ background: catStyle.bg, color: catStyle.color }}>
                              {m.category.replace('_', ' ')}
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

              {selectedProfileId && (
                <div className="mb-4">
                  <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: '#6B6B8A' }}>
                    Profil
                  </p>
                  <span className="text-xs font-semibold px-2 py-1 rounded-lg"
                        style={{ background: '#FFF7E6', color: '#FFB347' }}>
                    {profiles.find(p => p.id === selectedProfileId)?.name ?? ''}
                  </span>
                </div>
              )}

              <div className="mb-4">
                <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: '#6B6B8A' }}>
                  Modules sélectionnés ({noModulesSelected ? `0 → Reconnaissance` : selectedModules.size})
                </p>
                <div className="flex flex-wrap gap-1">
                  {(noModulesSelected
                    ? RECON_SLUGS.slice(0, 4)
                    : selectedModuleNames.slice(0, 4)
                  ).map(name => (
                    <span key={name} className="text-[10px] px-2 py-0.5 rounded-full font-medium"
                          style={{ background: noModulesSelected ? '#FFF7E6' : '#F0EEFF',
                                   color: noModulesSelected ? '#FFB347' : '#7C6FF7' }}>
                      {name}
                    </span>
                  ))}
                  {!noModulesSelected && selectedModuleNames.length > 4 && (
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

              {/* Limites */}
              {limits && (
                <div className="mb-3 rounded-xl p-3" style={{ background: '#F0EEFF' }}>
                  <p className="text-[10px] font-bold uppercase tracking-wider mb-2" style={{ color: '#6B6B8A' }}>
                    Mes limites
                  </p>
                  <div className="space-y-1.5">
                    {[
                      { label: "Aujourd'hui", used: limits.remaining.todayUsed, max: limits.remaining.todayMax },
                      { label: 'Ce mois',     used: limits.remaining.monthUsed, max: limits.remaining.monthMax },
                    ].map(({ label, used, max }) => (
                      <div key={label}>
                        <div className="flex justify-between text-[10px] mb-0.5">
                          <span style={{ color: '#6B6B8A' }}>{label}</span>
                          <span className="font-mono font-bold"
                                style={{ color: used >= max ? '#FF6B6B' : '#7C6FF7' }}>
                            {used}/{max}
                          </span>
                        </div>
                        <div className="w-full rounded-full h-1.5" style={{ background: '#EDE8FF' }}>
                          <div className="h-1.5 rounded-full"
                               style={{ width: `${Math.min(100, (used / max) * 100)}%`, background: used >= max ? '#FF6B6B' : '#7C6FF7' }} />
                        </div>
                      </div>
                    ))}
                  </div>
                  {limits.remaining.todayRemaining === 0 && (
                    <p className="text-xs mt-2 text-center font-semibold" style={{ color: '#FF6B6B' }}>
                      Limite journalière atteinte
                    </p>
                  )}
                </div>
              )}

              <button
                onClick={handleSubmit(onSubmit)}
                disabled={isSubmitting || (limits?.remaining.todayRemaining === 0 && limits?.permissions.maxScansPerDay < 9999)}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl font-bold text-sm text-white mb-2 transition-all disabled:opacity-50"
                style={{ background: '#FF6B6B' }}
              >
                <Play size={15} />
                {isSubmitting ? 'Lancement…' : 'Lancer le scan'}
              </button>
              <button
                type="button"
                onClick={() => { setShowSaveModal(true); setSaveError(''); profileForm.reset(); }}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl font-medium text-sm transition-all"
                style={{ border: '1px solid #EDE8FF', color: '#6B6B8A' }}
              >
                <BookmarkIcon size={13} />
                Sauvegarder en profil
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

      {/* ── Save Profile Modal ─────────────────────────────────────── */}
      {showSaveModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center"
             style={{ background: 'rgba(28,28,46,0.55)' }}
             onClick={e => { if (e.target === e.currentTarget) setShowSaveModal(false); }}>
          <div className="bg-white rounded-2xl p-6 w-full max-w-md shadow-2xl"
               style={{ border: '1px solid #EDE8FF' }}>
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg flex items-center justify-center"
                     style={{ background: '#FFF7E6' }}>
                  <Bookmark size={14} style={{ color: '#FFB347' }} />
                </div>
                <h2 className="font-bold text-navy text-sm">Sauvegarder comme profil</h2>
              </div>
              <button onClick={() => setShowSaveModal(false)}
                      className="p-1 rounded-lg hover:bg-gray-100 transition-all">
                <X size={16} style={{ color: '#6B6B8A' }} />
              </button>
            </div>

            <form onSubmit={profileForm.handleSubmit(onSaveProfile)} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-navy mb-1.5 uppercase tracking-wide">
                  Nom du profil *
                </label>
                <input
                  {...profileForm.register('profileName')}
                  placeholder="Mon profil personnalisé"
                  className="w-full px-4 py-2.5 rounded-xl text-sm outline-none"
                  style={{ border: profileForm.formState.errors.profileName ? '1.5px solid #FF6B6B' : '1.5px solid #EDE8FF', background: '#FAFAFA' }}
                />
                {profileForm.formState.errors.profileName && (
                  <p className="text-xs mt-1" style={{ color: '#FF6B6B' }}>
                    {profileForm.formState.errors.profileName.message}
                  </p>
                )}
              </div>

              <div>
                <label className="block text-xs font-bold text-navy mb-1.5 uppercase tracking-wide">
                  Description (optionnelle)
                </label>
                <textarea
                  {...profileForm.register('profileDesc')}
                  placeholder="Description du profil…"
                  rows={2}
                  className="w-full px-4 py-2.5 rounded-xl text-sm outline-none resize-none"
                  style={{ border: '1.5px solid #EDE8FF', background: '#FAFAFA' }}
                />
              </div>

              <div className="rounded-xl p-3" style={{ background: '#F0EEFF' }}>
                <p className="text-xs" style={{ color: '#7C6FF7' }}>
                  <strong>{selectedModules.size}</strong> module(s) sélectionné(s) seront sauvegardés dans ce profil.
                </p>
              </div>

              {saveError && (
                <p className="text-xs" style={{ color: '#FF6B6B' }}>{saveError}</p>
              )}

              <div className="flex gap-3 pt-1">
                <button
                  type="button"
                  onClick={() => setShowSaveModal(false)}
                  className="flex-1 py-2.5 rounded-xl text-sm font-medium transition-all"
                  style={{ border: '1px solid #EDE8FF', color: '#6B6B8A' }}
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  disabled={saveMutation.isPending}
                  className="flex-1 py-2.5 rounded-xl text-sm font-bold text-white transition-all disabled:opacity-50"
                  style={{ background: '#7C6FF7' }}
                >
                  {saveMutation.isPending ? 'Sauvegarde…' : 'Sauvegarder'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </Layout>
  );
}
