import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Trash2, ExternalLink, ChevronLeft, ChevronRight,
  ScanLine, Loader, CheckCircle2, XCircle, Clock,
} from 'lucide-react';
import { Layout, TopBar } from '@/components/ui/Layout';
import { ConfirmModal }   from '@/components/ui/ConfirmModal';
import { Toast }          from '@/components/ui/Toast';
import api from '@/services/api';
import type { PaginatedScans, Scan } from '@/types';

const LIMIT = 10;

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

export default function ScansListPage() {
  const navigate    = useNavigate();
  const queryClient = useQueryClient();
  const [page,     setPage]     = useState(1);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [toast,    setToast]    = useState<{ msg: string; type: 'success'|'error' } | null>(null);

  const { data, isLoading } = useQuery<{ data: { data: PaginatedScans } }>({
    queryKey: ['scans', page],
    queryFn:  () => api.get(`/scans?page=${page}&limit=${LIMIT}`),
  });
  const paged      = data?.data?.data;
  const scans      = paged?.scans ?? [];
  const total      = paged?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / LIMIT));

  const { mutate: deleteScan, isPending: deleting } = useMutation({
    mutationFn: (id: string) => api.delete(`/scans/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      setDeleteId(null);
      setToast({ msg: 'Scan supprimé', type: 'success' });
    },
    onError: () => setToast({ msg: 'Erreur lors de la suppression', type: 'error' }),
  });

  const today = new Date().toLocaleDateString('fr-FR', {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
  });

  return (
    <Layout>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
      <ConfirmModal
        isOpen={!!deleteId}
        title="Supprimer le scan"
        message="Cette action est irréversible. Toutes les vulnérabilités associées seront supprimées."
        onConfirm={() => deleteId && deleteScan(deleteId)}
        onCancel={() => setDeleteId(null)}
        loading={deleting}
      />

      <TopBar
        title="Mes scans"
        subtitle={`${today.charAt(0).toUpperCase() + today.slice(1)} — ${total} scan${total > 1 ? 's' : ''} au total`}
      />

      <div className="px-8 py-6">
        <div className="bg-white rounded-2xl overflow-hidden" style={{ border: '1px solid #EDE8FF' }}>
          {isLoading ? (
            <div className="p-12 flex justify-center">
              <Loader size={24} className="animate-spin" style={{ color: '#7C6FF7' }} />
            </div>
          ) : scans.length === 0 ? (
            <div className="p-14 text-center">
              <ScanLine size={28} className="mx-auto mb-3" style={{ color: '#EDE8FF' }} />
              <p className="font-medium text-navy mb-4">Aucun scan</p>
              <button onClick={() => navigate('/scans/new')}
                      className="px-4 py-2 rounded-xl text-sm font-semibold text-white"
                      style={{ background: '#FF6B6B' }}>
                Lancer un scan
              </button>
            </div>
          ) : (
            <>
              <div className="grid gap-4 px-6 py-3 text-[10px] font-bold uppercase tracking-wider"
                   style={{
                     gridTemplateColumns: '2.5fr 1fr 1fr 1fr auto',
                     background: '#FAFAFA', borderBottom: '1px solid #EDE8FF', color: '#6B6B8A',
                   }}>
                <div>URL Cible</div>
                <div>Statut</div>
                <div>Date</div>
                <div>Profondeur</div>
                <div />
              </div>

              {scans.map(scan => (
                <div key={scan.id}
                     className="grid gap-4 px-6 py-4 cursor-pointer group transition-all"
                     style={{ gridTemplateColumns: '2.5fr 1fr 1fr 1fr auto', borderBottom: '1px solid #F8F6FF' }}
                     onClick={() => navigate(
                       scan.status === 'COMPLETED' || scan.status === 'FAILED'
                         ? `/scans/${scan.id}/results` : `/scans/${scan.id}/live`
                     )}
                     onMouseEnter={e => (e.currentTarget.style.background = '#FAFAFE')}
                     onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="font-mono text-sm text-navy truncate">{scan.targetUrl}</span>
                    <ExternalLink size={12} className="shrink-0 opacity-0 group-hover:opacity-100 transition-all"
                                 style={{ color: '#7C6FF7' }} />
                  </div>
                  <div className="flex items-center">{statusPill(scan.status)}</div>
                  <div className="flex items-center text-sm" style={{ color: '#6B6B8A' }}>
                    {new Date(scan.createdAt).toLocaleDateString('fr-FR')}
                  </div>
                  <div className="flex items-center text-sm capitalize" style={{ color: '#6B6B8A' }}>
                    {scan.depth}
                  </div>
                  <div className="flex items-center justify-end">
                    <button
                      onClick={e => { e.stopPropagation(); setDeleteId(scan.id); }}
                      className="w-7 h-7 rounded-lg flex items-center justify-center transition-all opacity-0 group-hover:opacity-100"
                      style={{ color: '#6B6B8A' }}
                      onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = '#FFF0F0'; (e.currentTarget as HTMLButtonElement).style.color = '#FF6B6B'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = 'transparent'; (e.currentTarget as HTMLButtonElement).style.color = '#6B6B8A'; }}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </>
          )}
        </div>

        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-4 text-sm">
            <span style={{ color: '#6B6B8A' }}>Page {page} sur {totalPages}</span>
            <div className="flex gap-2">
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                      className="w-9 h-9 rounded-xl flex items-center justify-center transition-all disabled:opacity-40"
                      style={{ border: '1px solid #EDE8FF', color: '#6B6B8A' }}>
                <ChevronLeft size={16} />
              </button>
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}
                      className="w-9 h-9 rounded-xl flex items-center justify-center transition-all disabled:opacity-40"
                      style={{ border: '1px solid #EDE8FF', color: '#6B6B8A' }}>
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}
