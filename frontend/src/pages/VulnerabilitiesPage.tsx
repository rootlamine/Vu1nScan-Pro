import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ShieldAlert, Search, Loader, ChevronDown, ChevronUp, Code2, CheckCircle2 } from 'lucide-react';
import { Layout, TopBar } from '@/components/ui/Layout';
import api from '@/services/api';
import type { Vulnerability } from '@/types';

const SEV: Record<string, { label: string; bg: string; color: string }> = {
  CRITICAL: { label: 'CRITIQUE', bg: '#FFF0F0', color: '#FF6B6B' },
  HIGH:     { label: 'HAUTE',    bg: '#FFF7E6', color: '#FFB347' },
  MEDIUM:   { label: 'MOYENNE',  bg: '#F0EEFF', color: '#7C6FF7' },
  LOW:      { label: 'FAIBLE',   bg: '#E8FFFE', color: '#4ECDC4' },
};

export default function VulnerabilitiesPage() {
  const [search,   setSearch]   = useState('');
  const [severity, setSeverity] = useState('');
  const [openId,   setOpenId]   = useState<string | null>(null);

  const { data, isLoading } = useQuery<{ data: { data: Vulnerability[] } }>({
    queryKey: ['all-vulns', severity, search],
    queryFn:  () => {
      const p = new URLSearchParams();
      if (severity) p.set('severity', severity);
      if (search)   p.set('search',   search);
      return api.get(`/vulnerabilities?${p}`);
    },
  });
  const vulns = data?.data?.data ?? [];

  const today = new Date().toLocaleDateString('fr-FR', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });

  return (
    <Layout>
      <TopBar
        title="Vulnérabilités"
        subtitle={`${today} — Toutes les vulnérabilités détectées`}
      />
      <div className="px-8 py-6">
        {/* Filtres */}
        <div className="bg-white rounded-2xl p-4 mb-5 flex items-center gap-3 flex-wrap"
             style={{ border: '1px solid #EDE8FF' }}>
          <div className="relative flex-1 min-w-[200px]">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Rechercher une vulnérabilité…"
              className="w-full pl-9 pr-4 py-2.5 rounded-xl text-sm outline-none"
              style={{ border: '1px solid #EDE8FF', background: '#FAFAFA' }}
            />
          </div>
          <div className="flex gap-1">
            {[
              { v: '',         l: 'Toutes'  },
              { v: 'CRITICAL', l: 'Critique' },
              { v: 'HIGH',     l: 'Haute'   },
              { v: 'MEDIUM',   l: 'Moyenne' },
              { v: 'LOW',      l: 'Faible'  },
            ].map(f => (
              <button key={f.v} onClick={() => setSeverity(f.v)}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all"
                      style={severity === f.v
                        ? { background: '#1C1C2E', color: '#fff' }
                        : { background: '#F8F6FF', color: '#6B6B8A' }}>
                {f.l}
              </button>
            ))}
          </div>
        </div>

        {isLoading ? (
          <div className="flex justify-center py-16">
            <Loader size={24} className="animate-spin text-violet" />
          </div>
        ) : vulns.length === 0 ? (
          <div className="bg-white rounded-2xl py-16 text-center" style={{ border: '1px solid #EDE8FF' }}>
            <ShieldAlert size={28} className="mx-auto mb-3" style={{ color: '#EDE8FF' }} />
            <p className="font-medium text-navy">Aucune vulnérabilité trouvée</p>
          </div>
        ) : (
          <div className="space-y-3">
            {vulns.map(vuln => {
              const c = SEV[vuln.severity] ?? SEV.LOW;
              const open = openId === vuln.id;
              return (
                <div key={vuln.id} className="bg-white rounded-2xl overflow-hidden"
                     style={{ border: `1px solid ${open ? c.color : '#EDE8FF'}` }}>
                  <button
                    className="w-full flex items-center gap-3 px-5 py-4 text-left"
                    style={{ background: open ? c.bg : 'transparent' }}
                    onClick={() => setOpenId(open ? null : vuln.id)}
                  >
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold shrink-0"
                          style={{ background: c.bg, color: c.color, border: `1px solid ${c.color}40` }}>
                      {c.label}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className="font-semibold text-navy text-sm">{vuln.name}</p>
                      {vuln.endpoint && (
                        <p className="font-mono text-xs mt-0.5 truncate" style={{ color: '#6B6B8A' }}>
                          {vuln.endpoint}
                        </p>
                      )}
                    </div>
                    {vuln.cvssScore != null && (
                      <span className="font-mono text-xs font-bold px-2 py-0.5 rounded shrink-0"
                            style={{ background: c.bg, color: c.color }}>
                        {vuln.cvssScore.toFixed(1)}
                      </span>
                    )}
                    <span style={{ color: '#6B6B8A' }}>
                      {open ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                    </span>
                  </button>
                  {open && (
                    <div className="px-5 pb-5 pt-1 space-y-4">
                      <p className="text-sm leading-relaxed" style={{ color: '#6B6B8A' }}>
                        {vuln.description}
                      </p>
                      {vuln.payload && (
                        <pre className="rounded-xl px-4 py-3 text-xs font-mono overflow-x-auto"
                             style={{ background: '#1C1C2E', color: '#A8FFD8' }}>
                          {vuln.payload}
                        </pre>
                      )}
                      <div className="rounded-xl p-4" style={{ background: '#E8FFFE', borderLeft: '3px solid #4ECDC4' }}>
                        <p className="text-xs font-semibold mb-1 flex items-center gap-1.5"
                           style={{ color: '#2A9D8F' }}>
                          <CheckCircle2 size={13} /> Recommandation
                        </p>
                        <p className="text-sm" style={{ color: '#1C1C2E' }}>{vuln.recommendation}</p>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Layout>
  );
}
