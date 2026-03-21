import { useNavigate, useLocation } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Users, Shield, BarChart3, ScanLine, ShieldAlert, Loader, type LucideIcon,
} from 'lucide-react';
import { useState } from 'react';
import { Layout, TopBar } from '@/components/ui/Layout';
import { Toast }   from '@/components/ui/Toast';
import { useAuth } from '@/hooks/useAuth';
import api from '@/services/api';
import type { User, ScanModule, AdminStats } from '@/types';

/* ── KPI Card ─────────────────────────────────────────────────────── */
function KpiCard({ title, value, icon: Icon, topColor, iconBg, iconColor }: {
  title: string; value: number; icon: LucideIcon;
  topColor: string; iconBg: string; iconColor: string;
}) {
  return (
    <div className="bg-white rounded-2xl p-5 relative overflow-hidden" style={{ border: '1px solid #EDE8FF' }}>
      <div className="absolute top-0 left-0 right-0 h-0.5 rounded-t-2xl" style={{ background: topColor }} />
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium mb-2" style={{ color: '#6B6B8A' }}>{title}</p>
          <p className="font-mono text-2xl font-bold text-navy">{value}</p>
        </div>
        <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0" style={{ background: iconBg }}>
          <Icon size={18} className={iconColor} />
        </div>
      </div>
    </div>
  );
}

/* ── Page ─────────────────────────────────────────────────────────── */
export default function AdminPage() {
  const { user: me } = useAuth();
  const navigate     = useNavigate();
  const location     = useLocation();
  const queryClient  = useQueryClient();
  const [toast, setToast] = useState<{ msg: string; type: 'success'|'error' } | null>(null);

  if (me && me.role !== 'ADMIN') { navigate('/dashboard'); return null; }

  // Determine active tab from route
  const tab = location.pathname.includes('/modules') ? 'modules'
    : location.pathname.includes('/stats')   ? 'stats'
    : 'users';

  const { data: usersData }   = useQuery<{ data: { data: User[] } }>({
    queryKey: ['admin-users'],
    queryFn:  () => api.get('/admin/users'),
    enabled:  tab === 'users',
  });
  const { data: modulesData } = useQuery<{ data: { data: ScanModule[] } }>({
    queryKey: ['admin-modules'],
    queryFn:  () => api.get('/admin/modules'),
    enabled:  tab === 'modules',
  });
  const { data: statsData }   = useQuery<{ data: { data: AdminStats } }>({
    queryKey: ['admin-stats'],
    queryFn:  () => api.get('/admin/stats'),
    enabled:  tab === 'stats',
  });

  const users   = usersData?.data?.data   ?? [];
  const modules = modulesData?.data?.data ?? [];
  const stats   = statsData?.data?.data;

  const { mutate: updateUser } = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<User> }) =>
      api.patch(`/admin/users/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      setToast({ msg: 'Utilisateur mis à jour', type: 'success' });
    },
    onError: () => setToast({ msg: 'Erreur', type: 'error' }),
  });

  const { mutate: updateModule } = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ScanModule> }) =>
      api.patch(`/admin/modules/${id}`, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-modules'] });
      queryClient.invalidateQueries({ queryKey: ['modules'] });
      setToast({ msg: 'Module mis à jour', type: 'success' });
    },
    onError: () => setToast({ msg: 'Erreur', type: 'error' }),
  });

  const tabLabel = tab === 'users' ? 'Utilisateurs' : tab === 'modules' ? 'Modules' : 'Statistiques';

  return (
    <Layout>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
      <TopBar title={`Administration — ${tabLabel}`} subtitle="Gestion de la plateforme" />

      <div className="px-8 py-6">

        {/* ── Utilisateurs ─────────────────────────────────────────── */}
        {tab === 'users' && (
          <div className="bg-white rounded-2xl overflow-hidden" style={{ border: '1px solid #EDE8FF' }}>
            <div className="px-6 py-3.5 text-xs font-semibold uppercase tracking-wider"
                 style={{ borderBottom: '1px solid #EDE8FF', background: '#FAFAFA', color: '#6B6B8A' }}>
              {users.length} utilisateur{users.length > 1 ? 's' : ''}
            </div>
            {users.map((u, i) => (
              <div key={u.id}
                   className="flex items-center gap-4 px-6 py-4 transition-all"
                   style={{ borderBottom: i < users.length - 1 ? '1px solid #F8F6FF' : 'none' }}
                   onMouseEnter={e => (e.currentTarget.style.background = '#FAFAFE')}
                   onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                <div className="w-9 h-9 rounded-full flex items-center justify-center text-sm font-bold text-white shrink-0"
                     style={{ background: u.role === 'ADMIN' ? '#FF6B6B' : '#7C6FF7' }}>
                  {u.username[0].toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="font-semibold text-navy text-sm">{u.username}</p>
                  <p className="text-xs" style={{ color: '#6B6B8A' }}>{u.email}</p>
                </div>
                <select
                  value={u.role}
                  onChange={e => updateUser({ id: u.id, data: { role: e.target.value as 'USER'|'ADMIN' } })}
                  disabled={u.id === me?.id}
                  className="text-xs rounded-lg px-2.5 py-1.5 outline-none font-semibold disabled:opacity-50"
                  style={{ border: '1px solid #EDE8FF', color: '#7C6FF7', background: '#F0EEFF' }}
                >
                  <option value="USER">USER</option>
                  <option value="ADMIN">ADMIN</option>
                </select>
                <label className="flex items-center gap-1.5 text-xs cursor-pointer select-none"
                       style={{ color: '#6B6B8A' }}>
                  <input type="checkbox" checked={u.isActive}
                         onChange={e => updateUser({ id: u.id, data: { isActive: e.target.checked } })}
                         disabled={u.id === me?.id} className="accent-violet" />
                  Actif
                </label>
              </div>
            ))}
          </div>
        )}

        {/* ── Modules ──────────────────────────────────────────────── */}
        {tab === 'modules' && (
          <div className="space-y-3">
            {modules.map(mod => (
              <div key={mod.id} className="bg-white rounded-xl px-5 py-4 flex items-center gap-4"
                   style={{ border: '1px solid #EDE8FF' }}>
                <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
                     style={{ background: mod.isActive ? '#F0EEFF' : '#F8F8F8' }}>
                  <Shield size={16} style={{ color: mod.isActive ? '#7C6FF7' : '#6B6B8A' }} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="font-semibold text-navy text-sm">{mod.name}</p>
                  <p className="text-xs mt-0.5" style={{ color: '#6B6B8A' }}>{mod.description}</p>
                </div>
                <label className="flex items-center gap-1.5 text-xs cursor-pointer" style={{ color: '#6B6B8A' }}>
                  <input type="checkbox" checked={mod.isActive}
                         onChange={e => updateModule({ id: mod.id, data: { isActive: e.target.checked } })}
                         className="accent-violet" />
                  Actif
                </label>
                <label className="flex items-center gap-1.5 text-xs cursor-pointer" style={{ color: '#6B6B8A' }}>
                  <input type="checkbox" checked={mod.defaultEnabled}
                         onChange={e => updateModule({ id: mod.id, data: { defaultEnabled: e.target.checked } })}
                         className="accent-violet" />
                  Par défaut
                </label>
              </div>
            ))}
          </div>
        )}

        {/* ── Statistiques ─────────────────────────────────────────── */}
        {tab === 'stats' && (
          <div className="space-y-6">
            {stats ? (
              <>
                <div className="grid grid-cols-3 gap-4">
                  <KpiCard title="Utilisateurs"   value={stats.totalUsers} icon={Users}      topColor="#7C6FF7" iconBg="#F0EEFF" iconColor="text-violet" />
                  <KpiCard title="Scans total"    value={stats.totalScans} icon={ScanLine}   topColor="#4ECDC4" iconBg="#E8FFFE" iconColor="text-success" />
                  <KpiCard title="Vulnérabilités" value={stats.totalVulns} icon={ShieldAlert} topColor="#FF6B6B" iconBg="#FFF0F0" iconColor="text-coral" />
                </div>
                <div className="bg-white rounded-2xl p-6" style={{ border: '1px solid #EDE8FF' }}>
                  <h3 className="font-semibold text-navy mb-5 text-sm">Répartition par statut</h3>
                  <div className="space-y-3">
                    {Object.entries(stats.scansByStatus ?? {}).map(([status, count]) => {
                      const pct = stats.totalScans > 0 ? (count / stats.totalScans) * 100 : 0;
                      const colors: Record<string, string> = {
                        COMPLETED: '#4ECDC4', RUNNING: '#7C6FF7', FAILED: '#FF6B6B', PENDING: '#FFB347',
                      };
                      return (
                        <div key={status} className="flex items-center gap-3">
                          <span className="text-xs font-semibold w-24 shrink-0 text-navy">{status}</span>
                          <div className="flex-1 rounded-full h-2" style={{ background: '#EDE8FF' }}>
                            <div className="h-2 rounded-full transition-all"
                                 style={{ width: `${pct}%`, background: colors[status] ?? '#7C6FF7' }} />
                          </div>
                          <span className="font-mono text-sm font-bold text-navy w-8 text-right shrink-0">{count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </>
            ) : (
              <div className="flex items-center justify-center h-40">
                <Loader size={24} className="animate-spin text-violet" />
              </div>
            )}
          </div>
        )}
      </div>
    </Layout>
  );
}
