import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowLeft, Shield, ChevronDown, ChevronUp, Play,
  BookmarkIcon, AlertTriangle, CheckCircle2, Clock,
} from 'lucide-react';
import { Layout } from '@/components/ui/Layout';
import api from '@/services/api';
import type { ScanModule } from '@/types';

/* ── form schema ──────────────────────────────────────────────────── */
const schema = z.object({
  targetUrl:   z.string().url('URL invalide (ex: http://exemple.com)'),
  description: z.string().max(500).optional(),
  depth:       z.enum(['fast', 'normal', 'deep']).default('normal'),
  threads:     z.coerce.number().min(1).max(10).default(5),
});
type FormData = z.infer<typeof schema>;

/* ── severity config ──────────────────────────────────────────────── */
const SEV_CFG: Record<string, { label: string; bg: string; color: string }> = {
  CRITICAL: { label: 'CRITIQUE', bg: '#FFF0F0', color: '#FF6B6B' },
  HIGH:     { label: 'HAUTE',    bg: '#FFF7E6', color: '#FFB347' },
  MEDIUM:   { label: 'MOYENNE',  bg: '#F0EEFF', color: '#7C6FF7' },
  LOW:      { label: 'FAIBLE',   bg: '#E8FFFE', color: '#4ECDC4' },
};

/* Module cvss mapping */
const MODULE_META: Record<string, { severity: string; cvss: number; icon: string }> = {
  sql_injection:             { severity: 'CRITICAL', cvss: 9.8, icon: '≡' },
  xss_scanner:               { severity: 'HIGH',     cvss: 7.2, icon: '<>' },
  port_scanner:              { severity: 'HIGH',     cvss: 9.1, icon: '⋮' },
  http_headers:              { severity: 'MEDIUM',   cvss: 7.5, icon: '✉' },
  ssl_checker:               { severity: 'MEDIUM',   cvss: 5.3, icon: '🔒' },
  csrf_scanner:              { severity: 'MEDIUM',   cvss: 6.5, icon: '↺' },
  directory_traversal:       { severity: 'HIGH',     cvss: 7.5, icon: '📁' },
  open_redirect:             { severity: 'MEDIUM',   cvss: 6.1, icon: '→' },
  security_misconfiguration: { severity: 'HIGH',     cvss: 7.2, icon: '⚙' },
  sensitive_files:           { severity: 'MEDIUM',   cvss: 5.8, icon: '📄' },
};

/* ── depth options ────────────────────────────────────────────────── */
const DEPTH_OPTS = [
  { value: 'fast',   label: 'Rapide (~5 min)'  },
  { value: 'normal', label: 'Normal (~15 min)' },
  { value: 'deep',   label: 'Approfondi (~45 min)' },
] as const;

const THREAD_OPTS = [
  { value: '1', label: '1 thread (prudent)' },
  { value: '3', label: '3 threads'          },
  { value: '5', label: '5 threads'          },
  { value: '10',label: '10 threads (rapide)'},
] as const;

/* ── page ─────────────────────────────────────────────────────────── */
export default function NewScanPage() {
  const navigate = useNavigate();
  const [submitError,      setSubmitError]      = useState('');
  const [selectedModules,  setSelectedModules]  = useState<Set<string>>(new Set());
  const [optionsOpen,      setOptionsOpen]      = useState(false);
  const [urlValue,         setUrlValue]         = useState('');
  const [urlAccessible,    setUrlAccessible]    = useState<boolean | null>(null);

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

  const { register, handleSubmit, watch, formState: { errors, isSubmitting } } =
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

  const onSubmit = async (data: FormData) => {
    setSubmitError('');
    try {
      const res = await api.post('/scans', { ...data, threads: Number(data.threads) });
      navigate(`/scans/${res.data.data.id}/live`);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })
        ?.response?.data?.message ?? 'Erreur lors du lancement';
      setSubmitError(msg);
    }
  };

  // Extract domain from URL for sidebar display
  const urlDomain = urlValue.replace(/^https?:\/\//, '').replace(/\/.*$/, '') || '—';
  const selectedModuleNames = modules.filter(m => selectedModules.has(m.id)).map(m => m.name.split(' ')[0]);

  const DEPTH_LABEL: Record<string, string> = {
    fast: 'Rapide', normal: 'Normal', deep: 'Approfondi',
  };
  const estimatedTime = {
    fast: '~5 minutes', normal: '~20 minutes', deep: '~45 minutes',
  }[depth] ?? '~20 minutes';

  return (
    <Layout>
      {/* ── Topbar custom ────────────────────────────────────────── */}
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
        <div className="text-xs" style={{ color: '#6B6B8A' }}>
          Scans &gt; Nouveau
        </div>
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
              <div className="w-7 h-7 rounded-lg flex items-center justify-center"
                   style={{ background: '#F0EEFF' }}>
                <Shield size={14} className="text-violet" />
              </div>
              <div>
                <p className="font-bold text-navy text-sm">Cible du scan</p>
                <p className="text-xs" style={{ color: '#6B6B8A' }}>URL complète du système à analyser</p>
              </div>
            </div>

            {/* URL input */}
            <div className="flex items-stretch rounded-xl overflow-hidden mb-3"
                 style={{ border: errors.targetUrl ? '1.5px solid #FF6B6B' : '1.5px solid #EDE8FF' }}>
              <div className="flex items-center px-3 font-mono text-sm shrink-0"
                   style={{ background: '#F8F6FF', color: '#7C6FF7', borderRight: '1px solid #EDE8FF' }}>
                https://
              </div>
              <input
                {...register('targetUrl', { onChange: e => { setUrlValue(e.target.value); setUrlAccessible(null); } })}
                placeholder="testphp.vulnweb.com"
                className="flex-1 px-3 py-3 font-mono text-sm outline-none bg-white text-navy"
              />
              {urlValue && (
                <div className="flex items-center pr-3 gap-1.5">
                  <CheckCircle2 size={14} style={{ color: errors.targetUrl ? '#FF6B6B' : '#4ECDC4' }} />
                  <span className="text-xs font-semibold"
                        style={{ color: errors.targetUrl ? '#FF6B6B' : '#4ECDC4' }}>
                    {errors.targetUrl ? 'Invalide' : 'Accessible'}
                  </span>
                </div>
              )}
            </div>
            {errors.targetUrl && (
              <p className="text-xs mb-3" style={{ color: '#FF6B6B' }}>{errors.targetUrl.message}</p>
            )}

            <textarea
              {...register('description')}
              placeholder="Audit de sécurité — site de démonstration OWASP vulnweb"
              rows={2}
              className="w-full px-4 py-3 rounded-xl text-sm outline-none resize-none"
              style={{ border: '1.5px solid #EDE8FF', background: '#FAFAFA' }}
            />
          </div>

          {/* Modules de détection */}
          <div className="bg-white rounded-2xl p-6" style={{ border: '1px solid #EDE8FF' }}>
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg flex items-center justify-center"
                     style={{ background: '#FFF0F0' }}>
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

            <div className="space-y-0">
              {modules.map((m, i) => {
                const meta = MODULE_META[m.slug];
                const sev = meta ? SEV_CFG[meta.severity] : SEV_CFG.MEDIUM;
                const selected = selectedModules.has(m.id);
                return (
                  <div
                    key={m.id}
                    className="py-4 cursor-pointer transition-all"
                    style={{ borderBottom: i < modules.length - 1 ? '1px solid #F8F6FF' : 'none' }}
                    onClick={() => toggleModule(m.id)}
                  >
                    <div className="flex items-start gap-3">
                      {/* Icone module */}
                      <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 font-mono text-sm"
                           style={{ background: sev.bg, color: sev.color }}>
                        {meta?.icon ?? '⚡'}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="font-bold text-navy text-sm">{m.name}</p>
                        <p className="text-xs mt-0.5 leading-relaxed" style={{ color: '#6B6B8A' }}>
                          {m.description}
                        </p>
                        {meta && (
                          <span className="inline-flex items-center gap-1 mt-2 text-[10px] font-bold px-2 py-0.5 rounded-full"
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
              {optionsOpen ? <ChevronUp size={16} style={{ color: '#6B6B8A' }} /> : <ChevronDown size={16} style={{ color: '#6B6B8A' }} />}
            </button>

            {optionsOpen && (
              <div className="px-6 pb-6 grid grid-cols-2 gap-4"
                   style={{ borderTop: '1px solid #EDE8FF' }}>
                <div className="pt-4">
                  <label className="block text-xs font-bold text-navy mb-2 uppercase tracking-wide">
                    Profondeur d'analyse
                  </label>
                  <select
                    {...register('depth')}
                    className="w-full px-3 py-2.5 rounded-xl text-sm outline-none"
                    style={{ border: '1.5px solid #EDE8FF', background: '#FAFAFA' }}
                  >
                    {DEPTH_OPTS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                  </select>
                </div>
                <div className="pt-4">
                  <label className="block text-xs font-bold text-navy mb-2 uppercase tracking-wide">
                    Threads parallèles
                  </label>
                  <select
                    {...register('threads')}
                    className="w-full px-3 py-2.5 rounded-xl text-sm outline-none"
                    style={{ border: '1.5px solid #EDE8FF', background: '#FAFAFA' }}
                  >
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

              {/* URL */}
              <div className="mb-4">
                <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: '#6B6B8A' }}>
                  URL Cible
                </p>
                <p className="font-mono text-sm text-navy truncate">{urlDomain}</p>
              </div>

              {/* Modules */}
              <div className="mb-4">
                <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: '#6B6B8A' }}>
                  Modules sélectionnés ({selectedModules.size})
                </p>
                <div className="flex flex-wrap gap-1">
                  {selectedModuleNames.slice(0, 5).map(name => (
                    <span key={name} className="text-[10px] px-2 py-0.5 rounded-full font-medium"
                          style={{ background: '#F0EEFF', color: '#7C6FF7' }}>
                      {name}
                    </span>
                  ))}
                  {selectedModuleNames.length > 5 && (
                    <span className="text-[10px] px-2 py-0.5 rounded-full font-medium"
                          style={{ background: '#F0EEFF', color: '#7C6FF7' }}>
                      +{selectedModuleNames.length - 5}
                    </span>
                  )}
                </div>
              </div>

              {/* Config */}
              <div className="mb-5">
                <p className="text-[10px] font-bold uppercase tracking-wider mb-1.5" style={{ color: '#6B6B8A' }}>
                  Configuration
                </p>
                <div className="flex items-center gap-1.5 text-xs" style={{ color: '#6B6B8A' }}>
                  <Clock size={12} />
                  {DEPTH_LABEL[depth] ?? 'Normal'} · {threads || 5} thread{(threads || 5) > 1 ? 's' : ''}
                </div>
              </div>

              {/* Durée estimée */}
              <div className="mb-5 rounded-xl p-3" style={{ background: '#F8F6FF' }}>
                <p className="text-[10px] font-bold uppercase tracking-wider mb-1" style={{ color: '#6B6B8A' }}>
                  Durée estimée
                </p>
                <p className="font-bold text-navy text-sm">{estimatedTime}</p>
              </div>

              {/* Boutons */}
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

            {/* Warning */}
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
