import { useNavigate, useLocation } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Users, Shield, BarChart3, ScanLine, ShieldAlert, Loader, Search, X, Plus, Mail, Lock,
  User as UserIcon, LayoutList, LayoutGrid, Globe, Wifi, type LucideIcon,
} from 'lucide-react';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Layout, TopBar } from '@/components/ui/Layout';
import { Toast }   from '@/components/ui/Toast';
import { useAuth } from '@/hooks/useAuth';
import api from '@/services/api';
import type { User, ScanModule, AdminStats, ModuleCategory } from '@/types';

/* ── Create User Modal ───────────────────────────────────────────── */
const createUserSchema = z.object({
  username: z.string().min(3, 'Minimum 3 caractères').max(30),
  email:    z.string().email('Email invalide'),
  password: z.string().min(8, 'Minimum 8 caractères'),
  confirm:  z.string(),
  role:     z.enum(['USER', 'ADMIN']),
  isActive: z.boolean(),
}).refine(d => d.password === d.confirm, {
  message: 'Les mots de passe ne correspondent pas',
  path: ['confirm'],
});
type CreateUserForm = z.infer<typeof createUserSchema>;

function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const { register, handleSubmit, formState: { errors, isSubmitting }, setError } =
    useForm<CreateUserForm>({
      resolver: zodResolver(createUserSchema),
      defaultValues: { role: 'USER', isActive: true },
    });

  const inputStyle = (hasErr: boolean) => ({
    border:     `1.5px solid ${hasErr ? '#FF6B6B' : '#EDE8FF'}`,
    background: '#FAFAFA',
    borderRadius: '10px',
    padding: '10px 12px 10px 36px',
    width: '100%',
    fontSize: '0.875rem',
    outline: 'none',
    color: '#1C1C2E',
  } as React.CSSProperties);

  const onFocus  = (e: React.FocusEvent<HTMLInputElement|HTMLSelectElement>) => {
    e.currentTarget.style.borderColor = '#7C6FF7';
    e.currentTarget.style.boxShadow   = '0 0 0 3px rgba(124,111,247,.12)';
  };
  const onBlur = (hasErr: boolean) => (e: React.FocusEvent<HTMLInputElement|HTMLSelectElement>) => {
    e.currentTarget.style.borderColor = hasErr ? '#FF6B6B' : '#EDE8FF';
    e.currentTarget.style.boxShadow   = 'none';
  };

  const onSubmit = async (data: CreateUserForm) => {
    try {
      await api.post('/admin/users', {
        username: data.username,
        email:    data.email,
        password: data.password,
        role:     data.role,
        isActive: data.isActive,
      });
      onCreated();
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })
        ?.response?.data?.message ?? 'Erreur lors de la création';
      setError('root', { message: msg });
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center"
         style={{ background: 'rgba(28,28,46,.55)', backdropFilter: 'blur(4px)' }}
         onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md mx-4 relative"
           style={{ border: '1px solid #EDE8FF' }}>
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4" style={{ borderBottom: '1px solid #EDE8FF' }}>
          <h2 className="font-bold text-navy text-base">Ajouter un utilisateur</h2>
          <button onClick={onClose} className="w-8 h-8 flex items-center justify-center rounded-lg transition-all"
                  style={{ color: '#6B6B8A' }}
                  onMouseEnter={e => (e.currentTarget.style.background = '#F8F6FF')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
            <X size={16} />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit(onSubmit)} className="px-6 py-5 space-y-4">
          {errors.root && (
            <div className="rounded-xl p-3 text-sm text-center"
                 style={{ background: '#FFF0F0', color: '#FF6B6B', border: '1px solid #FFD0D0' }}>
              {errors.root.message}
            </div>
          )}

          {/* Username */}
          <div>
            <label className="block text-xs font-semibold text-navy mb-1.5">Nom d'utilisateur</label>
            <div className="relative">
              <UserIcon size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
              <input {...register('username')} placeholder="alice"
                     style={inputStyle(!!errors.username)} onFocus={onFocus} onBlur={onBlur(!!errors.username)} />
            </div>
            {errors.username && <p className="text-xs mt-1" style={{ color: '#FF6B6B' }}>{errors.username.message}</p>}
          </div>

          {/* Email */}
          <div>
            <label className="block text-xs font-semibold text-navy mb-1.5">Adresse email</label>
            <div className="relative">
              <Mail size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
              <input {...register('email')} type="email" placeholder="alice@exemple.com"
                     style={inputStyle(!!errors.email)} onFocus={onFocus} onBlur={onBlur(!!errors.email)} />
            </div>
            {errors.email && <p className="text-xs mt-1" style={{ color: '#FF6B6B' }}>{errors.email.message}</p>}
          </div>

          {/* Password */}
          <div>
            <label className="block text-xs font-semibold text-navy mb-1.5">Mot de passe</label>
            <div className="relative">
              <Lock size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
              <input {...register('password')} type="password" placeholder="Min. 8 caractères"
                     style={inputStyle(!!errors.password)} onFocus={onFocus} onBlur={onBlur(!!errors.password)} />
            </div>
            {errors.password && <p className="text-xs mt-1" style={{ color: '#FF6B6B' }}>{errors.password.message}</p>}
          </div>

          {/* Confirm */}
          <div>
            <label className="block text-xs font-semibold text-navy mb-1.5">Confirmer le mot de passe</label>
            <div className="relative">
              <Lock size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
              <input {...register('confirm')} type="password" placeholder="••••••••"
                     style={inputStyle(!!errors.confirm)} onFocus={onFocus} onBlur={onBlur(!!errors.confirm)} />
            </div>
            {errors.confirm && <p className="text-xs mt-1" style={{ color: '#FF6B6B' }}>{errors.confirm.message}</p>}
          </div>

          {/* Role + isActive */}
          <div className="flex gap-4 items-end">
            <div className="flex-1">
              <label className="block text-xs font-semibold text-navy mb-1.5">Rôle</label>
              <select {...register('role')}
                      className="w-full px-3 py-2.5 rounded-xl text-sm outline-none"
                      style={{ border: '1.5px solid #EDE8FF', background: '#FAFAFA', color: '#1C1C2E' }}
                      onFocus={onFocus} onBlur={onBlur(false)}>
                <option value="USER">USER</option>
                <option value="ADMIN">ADMIN</option>
              </select>
            </div>
            <div className="flex items-center gap-2 pb-2.5">
              <input {...register('isActive')} type="checkbox" id="isActive" className="accent-violet w-4 h-4" />
              <label htmlFor="isActive" className="text-xs font-semibold text-navy cursor-pointer">Compte actif</label>
            </div>
          </div>

          {/* Actions */}
          <div className="flex gap-3 pt-1">
            <button type="button" onClick={onClose}
                    className="flex-1 py-2.5 rounded-xl text-sm font-semibold transition-all"
                    style={{ border: '1.5px solid #EDE8FF', color: '#6B6B8A', background: '#FAFAFA' }}
                    onMouseEnter={e => (e.currentTarget.style.background = '#F0EEFF')}
                    onMouseLeave={e => (e.currentTarget.style.background = '#FAFAFA')}>
              Annuler
            </button>
            <button type="submit" disabled={isSubmitting}
                    className="flex-1 py-2.5 rounded-xl text-sm font-semibold text-white transition-all disabled:opacity-50"
                    style={{ background: '#FF6B6B' }}>
              {isSubmitting ? 'Création…' : 'Créer l\'utilisateur'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

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
  const [toast, setToast]         = useState<{ msg: string; type: 'success'|'error' } | null>(null);
  const [showAddUser, setShowAddUser] = useState(false);
  const [modSearch, setModSearch]  = useState('');
  const [modCat, setModCat]        = useState<'ALL' | ModuleCategory>('ALL');
  const [modPage, setModPage]      = useState(1);
  const [modView, setModView]      = useState<'list' | 'grid'>(() =>
    (localStorage.getItem('admin-mod-view') as 'list' | 'grid') || 'list'
  );
  const switchView = (v: 'list' | 'grid') => { setModView(v); localStorage.setItem('admin-mod-view', v); };

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
      {showAddUser && (
        <CreateUserModal
          onClose={() => setShowAddUser(false)}
          onCreated={() => {
            setShowAddUser(false);
            queryClient.invalidateQueries({ queryKey: ['admin-users'] });
            setToast({ msg: 'Utilisateur créé avec succès', type: 'success' });
          }}
        />
      )}
      <TopBar title={`Administration — ${tabLabel}`} subtitle="Gestion de la plateforme" />

      <div className="px-8 py-6">

        {/* ── Utilisateurs ─────────────────────────────────────────── */}
        {tab === 'users' && (
          <div className="space-y-4">
            {/* Toolbar */}
            <div className="flex items-center justify-between">
              <p className="text-xs font-semibold" style={{ color: '#6B6B8A' }}>
                {users.length} utilisateur{users.length !== 1 ? 's' : ''}
              </p>
              <button
                onClick={() => setShowAddUser(true)}
                className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-white transition-all"
                style={{ background: '#FF6B6B' }}
                onMouseEnter={e => (e.currentTarget.style.opacity = '0.88')}
                onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
              >
                <Plus size={15} />
                Ajouter un utilisateur
              </button>
            </div>
          <div className="bg-white rounded-2xl overflow-hidden" style={{ border: '1px solid #EDE8FF' }}>
            <div className="px-6 py-3.5 text-xs font-semibold uppercase tracking-wider"
                 style={{ borderBottom: '1px solid #EDE8FF', background: '#FAFAFA', color: '#6B6B8A' }}>
              Liste des comptes
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
          </div>
        )}

        {/* ── Modules ──────────────────────────────────────────────── */}
        {tab === 'modules' && (() => {
          const MOD_PAGE_SIZE = 8;
          const CAT_TABS: { key: 'ALL' | ModuleCategory; label: string; color: string }[] = [
            { key: 'ALL',              label: 'Tous',           color: '#7C6FF7' },
            { key: 'SECURITY',         label: 'Sécurité',       color: '#FF6B6B' },
            { key: 'WEB_OFFENSIVE',    label: 'Web Offensif',   color: '#E05252' },
            { key: 'API_OFFENSIVE',    label: 'API Offensif',   color: '#C0392B' },
            { key: 'NETWORK',          label: 'Réseau',         color: '#4ECDC4' },
            { key: 'NETWORK_OFFENSIVE',label: 'Réseau Offensif',color: '#2E86AB' },
            { key: 'OSINT',            label: 'OSINT',          color: '#7C6FF7' },
            { key: 'SCRAPING',         label: 'Scraping',       color: '#FFB347' },
            { key: 'SYSTEM',           label: 'Système',        color: '#8E44AD' },
          ];
          const CAT_BG: Record<string, string> = {
            SECURITY:          '#FFF0F0',
            NETWORK:           '#E8FFFE',
            OSINT:             '#F0EEFF',
            SCRAPING:          '#FFF8ED',
            WEB_OFFENSIVE:     '#FFE8E8',
            API_OFFENSIVE:     '#FFE0E0',
            NETWORK_OFFENSIVE: '#E0F0FF',
            SYSTEM:            '#F5E6FF',
          };

          const q = modSearch.toLowerCase();
          const filtered = modules.filter(m =>
            (modCat === 'ALL' || m.category === modCat) &&
            (q === '' || m.name.toLowerCase().includes(q) || m.description.toLowerCase().includes(q))
          );
          const totalPages = Math.max(1, Math.ceil(filtered.length / MOD_PAGE_SIZE));
          const safePage   = Math.min(modPage, totalPages);
          const paged      = filtered.slice((safePage - 1) * MOD_PAGE_SIZE, safePage * MOD_PAGE_SIZE);

          const goPage = (p: number) => setModPage(Math.max(1, Math.min(p, totalPages)));
          const resetPage = () => setModPage(1);

          return (
            <div className="space-y-4">
              {/* Search + category filters */}
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:gap-4">
                {/* Search bar */}
                <div className="relative flex-1">
                  <Search size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
                  <input
                    value={modSearch}
                    onChange={e => { setModSearch(e.target.value); resetPage(); }}
                    placeholder="Rechercher un module..."
                    className="w-full pl-9 pr-4 py-2.5 rounded-xl text-sm outline-none transition-all bg-white"
                    style={{ border: '1.5px solid #EDE8FF', color: '#1C1C2E' }}
                    onFocus={e => { e.currentTarget.style.borderColor = '#7C6FF7'; e.currentTarget.style.boxShadow = '0 0 0 3px rgba(124,111,247,.12)'; }}
                    onBlur={e =>  { e.currentTarget.style.borderColor = '#EDE8FF'; e.currentTarget.style.boxShadow = 'none'; }}
                  />
                </div>
                {/* Category tabs */}
                <div className="flex gap-1.5 flex-wrap">
                  {CAT_TABS.map(ct => (
                    <button
                      key={ct.key}
                      onClick={() => { setModCat(ct.key); resetPage(); }}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all"
                      style={modCat === ct.key
                        ? { background: ct.color, color: '#fff', border: `1.5px solid ${ct.color}` }
                        : { background: '#FAFAFA', color: '#6B6B8A', border: '1.5px solid #EDE8FF' }}
                    >
                      {ct.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Counter + view toggle */}
              {(() => {
                const CAT_ICON: Record<string, React.ReactNode> = {
                  SECURITY:          <Shield size={18} />,
                  NETWORK:           <Wifi   size={18} />,
                  OSINT:             <Globe  size={18} />,
                  SCRAPING:          <Search size={18} />,
                  WEB_OFFENSIVE:     <Shield size={18} />,
                  API_OFFENSIVE:     <Globe  size={18} />,
                  NETWORK_OFFENSIVE: <Wifi   size={18} />,
                  SYSTEM:            <Search size={18} />,
                };
                return (
                  <>
                    <div className="flex items-center justify-between">
                      {/* View toggle */}
                      <div className="flex rounded-lg overflow-hidden" style={{ border: '1.5px solid #EDE8FF' }}>
                        {(['list', 'grid'] as const).map((v, i) => (
                          <button key={v} onClick={() => switchView(v)}
                                  className="flex items-center justify-center w-8 h-8 transition-all"
                                  style={{
                                    background: modView === v ? '#7C6FF7' : 'transparent',
                                    borderRight: i === 0 ? '1px solid #EDE8FF' : 'none',
                                  }}>
                            {v === 'list'
                              ? <LayoutList  size={14} style={{ color: modView === v ? '#fff' : '#6B6B8A' }} />
                              : <LayoutGrid  size={14} style={{ color: modView === v ? '#fff' : '#6B6B8A' }} />}
                          </button>
                        ))}
                      </div>
                      {/* Counter */}
                      <p className="text-xs font-semibold" style={{ color: '#6B6B8A' }}>
                        {filtered.length} module{filtered.length !== 1 ? 's' : ''}{modSearch || modCat !== 'ALL' ? ' trouvés' : ''}
                      </p>
                    </div>

                    {/* Module list view */}
                    {modView === 'list' && (
                      <div className="space-y-3">
                        {paged.length === 0 ? (
                          <div className="bg-white rounded-xl px-5 py-8 text-center text-sm"
                               style={{ border: '1px solid #EDE8FF', color: '#6B6B8A' }}>
                            Aucun module trouvé
                          </div>
                        ) : paged.map(mod => (
                          <div key={mod.id} className="bg-white rounded-xl px-5 py-4 flex items-center gap-4 transition-all"
                               style={{ border: '1px solid #EDE8FF' }}
                               onMouseEnter={e => { e.currentTarget.style.borderColor = '#7C6FF7'; e.currentTarget.style.boxShadow = '0 2px 12px rgba(124,111,247,.1)'; }}
                               onMouseLeave={e => { e.currentTarget.style.borderColor = '#EDE8FF'; e.currentTarget.style.boxShadow = 'none'; }}>
                            <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
                                 style={{ background: mod.isActive ? '#F0EEFF' : '#F8F8F8' }}>
                              <Shield size={16} style={{ color: mod.isActive ? '#7C6FF7' : '#6B6B8A' }} />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-0.5">
                                <p className="font-semibold text-navy text-sm">{mod.name}</p>
                                {mod.category && (
                                  <span className="text-xs font-semibold px-1.5 py-0.5 rounded-md"
                                        style={{ background: CAT_BG[mod.category] ?? '#F0EEFF', color: CAT_TABS.find(t => t.key === mod.category)?.color ?? '#7C6FF7' }}>
                                    {mod.category}
                                  </span>
                                )}
                              </div>
                              <p className="text-xs" style={{ color: '#6B6B8A' }}>{mod.description}</p>
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

                    {/* Module grid view */}
                    {modView === 'grid' && (
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                        {paged.length === 0 ? (
                          <div className="col-span-3 bg-white rounded-xl px-5 py-8 text-center text-sm"
                               style={{ border: '1px solid #EDE8FF', color: '#6B6B8A' }}>
                            Aucun module trouvé
                          </div>
                        ) : paged.map(mod => {
                          const catColor = CAT_TABS.find(t => t.key === mod.category)?.color ?? '#7C6FF7';
                          return (
                            <div key={mod.id}
                                 className="bg-white rounded-xl p-5 flex flex-col gap-3 transition-all cursor-default"
                                 style={{ border: '1px solid #EDE8FF' }}
                                 onMouseEnter={e => { e.currentTarget.style.borderColor = '#7C6FF7'; e.currentTarget.style.boxShadow = '0 4px 16px rgba(124,111,247,.13)'; e.currentTarget.style.transform = 'translateY(-1px)'; }}
                                 onMouseLeave={e => { e.currentTarget.style.borderColor = '#EDE8FF'; e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.transform = 'none'; }}>
                              {/* Icon + badges row */}
                              <div className="flex items-center gap-2">
                                <div className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
                                     style={{ background: mod.isActive ? CAT_BG[mod.category] ?? '#F0EEFF' : '#F8F8F8', color: mod.isActive ? catColor : '#6B6B8A' }}>
                                  {CAT_ICON[mod.category] ?? <Shield size={18} />}
                                </div>
                                {mod.category && (
                                  <span className="text-xs font-semibold px-1.5 py-0.5 rounded-md"
                                        style={{ background: CAT_BG[mod.category] ?? '#F0EEFF', color: catColor }}>
                                    {mod.category}
                                  </span>
                                )}
                              </div>
                              {/* Name */}
                              <p className="font-bold text-navy text-sm leading-snug">{mod.name}</p>
                              {/* Description — 2 lines max */}
                              <p className="text-xs flex-1 line-clamp-2" style={{ color: '#6B6B8A', lineHeight: 1.6 }}>
                                {mod.description}
                              </p>
                              {/* Toggles */}
                              <div className="flex items-center gap-4 pt-1" style={{ borderTop: '1px solid #F8F6FF' }}>
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
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </>
                );
              })()}

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between pt-1">
                  <p className="text-xs" style={{ color: '#6B6B8A' }}>
                    Page {safePage} sur {totalPages}
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => goPage(safePage - 1)}
                      disabled={safePage === 1}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all disabled:opacity-40"
                      style={{ border: '1.5px solid #EDE8FF', color: '#6B6B8A', background: '#FAFAFA' }}
                    >
                      Précédent
                    </button>
                    {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
                      <button
                        key={p}
                        onClick={() => goPage(p)}
                        className="w-8 h-8 rounded-lg text-xs font-semibold transition-all"
                        style={p === safePage
                          ? { background: '#1C1C2E', color: '#fff', border: '1.5px solid #1C1C2E' }
                          : { border: '1.5px solid #EDE8FF', color: '#6B6B8A', background: '#FAFAFA' }}
                      >
                        {p}
                      </button>
                    ))}
                    <button
                      onClick={() => goPage(safePage + 1)}
                      disabled={safePage === totalPages}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold transition-all disabled:opacity-40"
                      style={{ border: '1.5px solid #EDE8FF', color: '#6B6B8A', background: '#FAFAFA' }}
                    >
                      Suivant
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })()}

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
