import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  CheckCircle2, XCircle, Clock, Loader, ChevronRight, ArrowLeft, Shield,
} from 'lucide-react';
import { Layout } from '@/components/ui/Layout';
import api from '@/services/api';
import type { Scan, ModuleStatus } from '@/types';

function statusPill(status: Scan['status']) {
  const cfg = {
    COMPLETED: { label: 'Terminé',    bg: '#E8FFFE', color: '#4ECDC4' },
    RUNNING:   { label: 'En cours',   bg: '#F0EEFF', color: '#7C6FF7' },
    FAILED:    { label: 'Échoué',     bg: '#FFF0F0', color: '#FF6B6B' },
    PENDING:   { label: 'En attente', bg: '#FFF7E6', color: '#FFB347' },
  } as const;
  const c = cfg[status] ?? cfg.PENDING;
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold"
          style={{ background: c.bg, color: c.color }}>
      {status === 'RUNNING' && <Loader size={11} className="animate-spin" />}
      {status === 'COMPLETED' && <CheckCircle2 size={11} />}
      {status === 'FAILED'    && <XCircle size={11} />}
      {status === 'PENDING'   && <Clock size={11} />}
      {c.label}
    </span>
  );
}

const MOD_CFG: Record<ModuleStatus, { icon: React.ReactNode; color: string }> = {
  PENDING: { icon: <Clock size={15} />,                              color: '#FFB347' },
  RUNNING: { icon: <Loader size={15} className="animate-spin" />,   color: '#7C6FF7' },
  DONE:    { icon: <CheckCircle2 size={15} />,                       color: '#4ECDC4' },
  ERROR:   { icon: <XCircle size={15} />,                            color: '#FF6B6B' },
};

export default function ScanLivePage() {
  const { id }   = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data, isLoading } = useQuery<{ data: { data: Scan } }>({
    queryKey: ['scan', id],
    queryFn:  () => api.get(`/scans/${id}`),
    refetchInterval: (query) => {
      const status = query.state.data?.data?.data?.status;
      return status === 'RUNNING' || status === 'PENDING' ? 3000 : false;
    },
  });

  const scan    = data?.data?.data;
  const isDone  = scan?.status === 'COMPLETED' || scan?.status === 'FAILED';
  const results = scan?.moduleResults ?? [];
  const total   = results.length;
  const done    = results.filter(r => r.status === 'DONE' || r.status === 'ERROR').length;
  const pct     = total > 0 ? Math.round((done / total) * 100) : 0;

  if (isLoading) return (
    <Layout>
      <div className="flex items-center justify-center h-screen">
        <Loader className="animate-spin" size={28} style={{ color: '#7C6FF7' }} />
      </div>
    </Layout>
  );

  if (!scan) return (
    <Layout>
      <div className="text-center py-16" style={{ color: '#6B6B8A' }}>Scan introuvable.</div>
    </Layout>
  );

  return (
    <Layout>
      {/* Topbar */}
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
          {statusPill(scan.status)}
        </div>
      </div>

      <div className="px-8 py-6 max-w-[720px] mx-auto">
        {/* URL */}
        <p className="font-mono text-sm mb-6 truncate" style={{ color: '#6B6B8A' }}>{scan.targetUrl}</p>

        {/* Progression */}
        <div className="bg-white rounded-2xl p-6 mb-5" style={{ border: '1px solid #EDE8FF' }}>
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Shield size={16} className="text-violet" />
              <span className="font-semibold text-navy text-sm">Progression globale</span>
            </div>
            <span className="font-mono font-bold text-sm" style={{ color: '#7C6FF7' }}>{pct}%</span>
          </div>
          <div className="w-full rounded-full h-2 mb-2" style={{ background: '#EDE8FF' }}>
            <div className="h-2 rounded-full transition-all duration-700"
                 style={{ width: `${pct}%`, background: scan.status === 'FAILED' ? '#FF6B6B' : '#7C6FF7' }} />
          </div>
          <p className="text-xs" style={{ color: '#6B6B8A' }}>{done}/{total} modules terminés</p>
        </div>

        {/* Modules */}
        <div className="bg-white rounded-2xl overflow-hidden" style={{ border: '1px solid #EDE8FF' }}>
          <div className="px-5 py-3.5" style={{ borderBottom: '1px solid #EDE8FF' }}>
            <h2 className="text-sm font-semibold text-navy">Modules d'analyse</h2>
          </div>
          {results.length === 0 ? (
            <div className="px-5 py-10 text-center">
              <Loader size={20} className="animate-spin mx-auto mb-2" style={{ color: '#7C6FF7' }} />
              <p className="text-sm" style={{ color: '#6B6B8A' }}>Initialisation des modules…</p>
            </div>
          ) : (
            results.map((result, i) => {
              const cfg = MOD_CFG[result.status];
              return (
                <div key={result.id}
                     className="flex items-center gap-4 px-5 py-4"
                     style={{ borderBottom: i < results.length - 1 ? '1px solid #F8F6FF' : 'none' }}>
                  <div style={{ color: cfg.color }} className="shrink-0">{cfg.icon}</div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-navy">{result.module.name}</p>
                    <p className="text-xs truncate mt-0.5" style={{ color: '#6B6B8A' }}>
                      {result.module.description}
                    </p>
                  </div>
                  {result.executionTime != null && (
                    <span className="font-mono text-xs shrink-0" style={{ color: '#6B6B8A' }}>
                      {(result.executionTime / 1000).toFixed(1)}s
                    </span>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Actions */}
        {isDone ? (
          <div className="mt-5 flex gap-3">
            <button onClick={() => navigate(`/scans/${id}/results`)}
                    className="flex-1 flex items-center justify-center gap-2 py-3 rounded-xl font-bold text-sm text-white"
                    style={{ background: '#FF6B6B' }}>
              Voir les résultats <ChevronRight size={16} />
            </button>
            <button onClick={() => navigate('/scans')}
                    className="px-5 py-3 rounded-xl font-medium text-sm transition-all"
                    style={{ border: '1px solid #EDE8FF', color: '#6B6B8A' }}>
              Retour
            </button>
          </div>
        ) : (
          <p className="text-xs text-center mt-4" style={{ color: '#6B6B8A' }}>
            Actualisation automatique toutes les 3 secondes…
          </p>
        )}
      </div>
    </Layout>
  );
}
