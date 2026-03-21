import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { FileText, Download, AlertTriangle, Loader } from 'lucide-react';
import { Layout, TopBar } from '@/components/ui/Layout';
import { Toast }  from '@/components/ui/Toast';
import api from '@/services/api';
import type { Report } from '@/types';

export default function ReportsPage() {
  const [toast,       setToast]       = useState<{ msg: string; type: 'success'|'error' } | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);

  const { data, isLoading } = useQuery<{ data: { data: Report[] } }>({
    queryKey: ['reports'],
    queryFn:  () => api.get('/reports'),
  });
  const reports = data?.data?.data ?? [];

  const handleDownload = async (report: Report) => {
    setDownloading(report.id);
    try {
      const res  = await api.get(`/reports/${report.id}/download`, { responseType: 'blob' });
      const url  = URL.createObjectURL(new Blob([res.data], { type: 'application/pdf' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = `vulnscan-report-${report.scanId}.pdf`;
      link.click();
      URL.revokeObjectURL(url);
    } catch {
      setToast({ msg: 'Erreur lors du téléchargement', type: 'error' });
    } finally {
      setDownloading(null);
    }
  };

  const today = new Date().toLocaleDateString('fr-FR', {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
  });

  return (
    <Layout>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
      <TopBar title="Rapports PDF" subtitle={`${today.charAt(0).toUpperCase() + today.slice(1)} — Téléchargez vos rapports de sécurité`} />

      <div className="px-8 py-6">
        <div className="bg-white rounded-2xl overflow-hidden" style={{ border: '1px solid #EDE8FF' }}>
          {isLoading ? (
            <div className="p-12 flex justify-center">
              <Loader size={24} className="animate-spin" style={{ color: '#7C6FF7' }} />
            </div>
          ) : reports.length === 0 ? (
            <div className="p-14 text-center">
              <AlertTriangle size={28} className="mx-auto mb-3" style={{ color: '#EDE8FF' }} />
              <p className="font-medium text-navy mb-1">Aucun rapport généré</p>
              <p className="text-sm" style={{ color: '#6B6B8A' }}>
                Générez un rapport depuis la page résultats d'un scan terminé
              </p>
            </div>
          ) : (
            <>
              <div className="grid gap-4 px-6 py-3 text-[10px] font-bold uppercase tracking-wider"
                   style={{
                     gridTemplateColumns: '2.5fr 2fr 1fr auto',
                     background: '#FAFAFA', borderBottom: '1px solid #EDE8FF', color: '#6B6B8A',
                   }}>
                <div>Scan analysé</div>
                <div>Date de génération</div>
                <div>Taille</div>
                <div className="text-right">Action</div>
              </div>
              {reports.map(report => (
                <div key={report.id}
                     className="grid gap-4 px-6 py-4 items-center transition-all"
                     style={{ gridTemplateColumns: '2.5fr 2fr 1fr auto', borderBottom: '1px solid #F8F6FF' }}
                     onMouseEnter={e => (e.currentTarget.style.background = '#FAFAFE')}
                     onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
                         style={{ background: '#F0EEFF' }}>
                      <FileText size={16} className="text-violet" />
                    </div>
                    <div className="min-w-0">
                      <p className="font-mono text-sm text-navy truncate">
                        {report.scan?.targetUrl ?? '—'}
                      </p>
                      <p className="font-mono text-xs mt-0.5" style={{ color: '#6B6B8A' }}>
                        #{report.scanId.slice(0, 8)}
                      </p>
                    </div>
                  </div>
                  <div className="text-sm" style={{ color: '#6B6B8A' }}>
                    {new Date(report.generatedAt).toLocaleDateString('fr-FR', {
                      day: 'numeric', month: 'short', year: 'numeric',
                      hour: '2-digit', minute: '2-digit',
                    })}
                  </div>
                  <div className="font-mono text-sm" style={{ color: '#6B6B8A' }}>
                    {report.fileSize ? `${(report.fileSize / 1024).toFixed(0)} ko` : '—'}
                  </div>
                  <div className="flex justify-end">
                    <button onClick={() => handleDownload(report)} disabled={downloading === report.id}
                            className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold text-white transition-all disabled:opacity-50"
                            style={{ background: '#1C1C2E' }}>
                      <Download size={13} />
                      {downloading === report.id ? '…' : 'PDF'}
                    </button>
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      </div>
    </Layout>
  );
}
