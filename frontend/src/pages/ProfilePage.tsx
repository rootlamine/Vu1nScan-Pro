import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { User, Lock, Shield, BarChart2, BookmarkIcon, Trash2, Gauge, Plus, X } from 'lucide-react';
import { Layout, TopBar } from '@/components/ui/Layout';
import { Toast }   from '@/components/ui/Toast';
import { useAuth } from '@/hooks/useAuth';
import api from '@/services/api';
import type { MyLimitsResp, ScanProfile, PaginatedScans } from '@/types';

const profileSchema = z.object({
  username: z.string().min(3).max(30).optional().or(z.literal('')),
  email:    z.string().email().optional().or(z.literal('')),
}).refine(d => d.username || d.email, { message: 'Remplissez au moins un champ' });

const passwordSchema = z.object({
  currentPassword: z.string().min(1, 'Requis'),
  newPassword:     z.string().min(8).regex(/[A-Z]/).regex(/[a-z]/).regex(/\d/),
  confirm:         z.string(),
}).refine(d => d.newPassword === d.confirm, {
  message: 'Les mots de passe ne correspondent pas', path: ['confirm'],
});

type ProfileForm  = z.infer<typeof profileSchema>;
type PasswordForm = z.infer<typeof passwordSchema>;

const inputCls   = 'w-full px-4 py-3 rounded-xl text-sm outline-none transition-all';
const inputStyle = { border: '1.5px solid #EDE8FF', background: '#FAFAFA', color: '#1C1C2E' };

function SectionTitle({ icon: Icon, title }: { icon: React.ElementType; title: string }) {
  return (
    <h2 className="font-semibold text-navy mb-4 flex items-center gap-2 text-sm">
      <Icon size={16} style={{ color: '#7C6FF7' }} /> {title}
    </h2>
  );
}

export default function ProfilePage() {
  const { user, login, token } = useAuth();
  const queryClient = useQueryClient();
  const [toast, setToast] = useState<{ msg: string; type: 'success'|'error' } | null>(null);
  const [editProfileId, setEditProfileId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');
  const [editDesc, setEditDesc] = useState('');

  const profileForm  = useForm<ProfileForm>({
    resolver: zodResolver(profileSchema),
    defaultValues: { username: user?.username ?? '', email: user?.email ?? '' },
  });
  const passwordForm = useForm<PasswordForm>({ resolver: zodResolver(passwordSchema) });

  // ── Queries ────────────────────────────────────────────────────────
  const { data: limitsData } = useQuery<{ data: { data: MyLimitsResp } }>({
    queryKey: ['my-limits'],
    queryFn:  () => api.get('/auth/me/limits'),
  });
  const limits = limitsData?.data?.data;

  const { data: profilesData } = useQuery<{ data: { data: ScanProfile[] } }>({
    queryKey: ['profiles'],
    queryFn:  () => api.get('/profiles'),
  });
  const scanProfiles = profilesData?.data?.data ?? [];

  const { data: scansData } = useQuery<{ data: { data: PaginatedScans } }>({
    queryKey: ['scans', 'profile'],
    queryFn:  () => api.get('/scans?limit=10&page=1'),
  });
  const recentScans = scansData?.data?.data?.scans ?? [];
  const totalScans  = scansData?.data?.data?.total ?? 0;

  // ── Mutations ──────────────────────────────────────────────────────
  const { mutate: deleteProfile } = useMutation({
    mutationFn: (id: string) => api.delete(`/profiles/${id}`),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['profiles'] }); setToast({ msg: 'Profil supprimé', type: 'success' }); },
    onError: () => setToast({ msg: 'Erreur', type: 'error' }),
  });
  const { mutate: updateProfile } = useMutation({
    mutationFn: ({ id, name, description }: { id: string; name: string; description?: string }) =>
      api.patch(`/profiles/${id}`, { name, description }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['profiles'] });
      setEditProfileId(null);
      setToast({ msg: 'Profil mis à jour', type: 'success' });
    },
    onError: () => setToast({ msg: 'Erreur', type: 'error' }),
  });

  const onProfileSubmit = async (data: ProfileForm) => {
    const payload: Record<string, string> = {};
    if (data.username) payload.username = data.username;
    if (data.email)    payload.email    = data.email;
    try {
      const res = await api.patch('/auth/profile', payload);
      if (token) login(token, res.data.data);
      setToast({ msg: 'Profil mis à jour', type: 'success' });
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? 'Erreur';
      setToast({ msg, type: 'error' });
    }
  };

  const onPasswordSubmit = async (data: PasswordForm) => {
    try {
      await api.patch('/auth/password', { currentPassword: data.currentPassword, newPassword: data.newPassword });
      passwordForm.reset();
      setToast({ msg: 'Mot de passe modifié', type: 'success' });
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? 'Erreur';
      setToast({ msg, type: 'error' });
    }
  };

  const SEV_COLORS: Record<string, string> = { COMPLETED: '#4ECDC4', RUNNING: '#7C6FF7', FAILED: '#FF6B6B', PENDING: '#FFB347' };
  const SEV_LABELS: Record<string, string> = { COMPLETED: 'Terminé', RUNNING: 'En cours', FAILED: 'Échoué', PENDING: 'En attente' };

  return (
    <Layout>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
      <TopBar title="Mon profil" subtitle="Gérer vos informations et sécurité du compte" />

      <div className="px-8 py-6 grid grid-cols-2 gap-6 max-w-4xl">

        {/* ── Colonne gauche ──────────────────────────────────────────── */}
        <div className="space-y-5">

          {/* Avatar card */}
          <div className="bg-white rounded-2xl p-5 flex items-center gap-4" style={{ border: '1px solid #EDE8FF' }}>
            <div className="w-14 h-14 rounded-2xl flex items-center justify-center text-2xl font-bold text-white shrink-0"
                 style={{ background: '#FF6B6B' }}>
              {user?.username?.[0]?.toUpperCase() ?? 'U'}
            </div>
            <div>
              <p className="font-bold text-navy">{user?.username}</p>
              <p className="text-sm" style={{ color: '#6B6B8A' }}>{user?.email}</p>
              <div className="mt-1.5 inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full"
                   style={{ background: user?.role === 'ADMIN' ? '#FFF0F0' : '#F0EEFF' }}>
                <Shield size={12} style={{ color: user?.role === 'ADMIN' ? '#FF6B6B' : '#7C6FF7' }} />
                <span className="text-xs font-bold font-mono"
                      style={{ color: user?.role === 'ADMIN' ? '#FF6B6B' : '#7C6FF7' }}>
                  {user?.role}
                </span>
              </div>
            </div>
          </div>

          {/* Informations */}
          <div className="bg-white rounded-2xl p-6" style={{ border: '1px solid #EDE8FF' }}>
            <SectionTitle icon={User} title="Informations générales" />
            <form onSubmit={profileForm.handleSubmit(onProfileSubmit)} className="space-y-4">
              <div>
                <label className="block text-xs font-bold text-navy mb-1.5 uppercase tracking-wide">
                  Nom d'utilisateur
                </label>
                <input {...profileForm.register('username')} className={inputCls} style={inputStyle} />
              </div>
              <div>
                <label className="block text-xs font-bold text-navy mb-1.5 uppercase tracking-wide">Email</label>
                <input {...profileForm.register('email')} type="email" className={inputCls} style={inputStyle} />
              </div>
              {profileForm.formState.errors.root && (
                <p className="text-xs" style={{ color: '#FF6B6B' }}>{profileForm.formState.errors.root.message}</p>
              )}
              <button type="submit" disabled={profileForm.formState.isSubmitting}
                      className="w-full py-3 rounded-xl font-semibold text-sm text-white disabled:opacity-50"
                      style={{ background: '#7C6FF7' }}>
                {profileForm.formState.isSubmitting ? 'Enregistrement…' : 'Enregistrer'}
              </button>
            </form>
          </div>

          {/* Mot de passe */}
          <div className="bg-white rounded-2xl p-6" style={{ border: '1px solid #EDE8FF' }}>
            <SectionTitle icon={Lock} title="Changer le mot de passe" />
            <form onSubmit={passwordForm.handleSubmit(onPasswordSubmit)} className="space-y-4">
              {(['currentPassword', 'newPassword', 'confirm'] as const).map(field => {
                const labels = { currentPassword: 'Mot de passe actuel', newPassword: 'Nouveau mot de passe', confirm: 'Confirmer' };
                const placeholders = { currentPassword: '••••••••', newPassword: 'Min. 8 car., maj., chiffre', confirm: '••••••••' };
                return (
                  <div key={field}>
                    <label className="block text-xs font-bold text-navy mb-1.5 uppercase tracking-wide">
                      {labels[field]}
                    </label>
                    <input {...passwordForm.register(field)} type="password" placeholder={placeholders[field]}
                           className={inputCls} style={inputStyle} />
                    {passwordForm.formState.errors[field] && (
                      <p className="text-xs mt-1" style={{ color: '#FF6B6B' }}>
                        {passwordForm.formState.errors[field]?.message}
                      </p>
                    )}
                  </div>
                );
              })}
              <button type="submit" disabled={passwordForm.formState.isSubmitting}
                      className="w-full py-3 rounded-xl font-semibold text-sm text-white disabled:opacity-50"
                      style={{ background: '#1C1C2E' }}>
                {passwordForm.formState.isSubmitting ? 'Modification…' : 'Changer le mot de passe'}
              </button>
            </form>
          </div>
        </div>

        {/* ── Colonne droite ──────────────────────────────────────────── */}
        <div className="space-y-5">

          {/* Mes limites */}
          <div className="bg-white rounded-2xl p-5" style={{ border: '1px solid #EDE8FF' }}>
            <SectionTitle icon={Gauge} title="Mes limites" />
            {limits ? (
              <div className="space-y-3">
                {[
                  { label: "Scans aujourd'hui", used: limits.remaining.todayUsed, max: limits.remaining.todayMax, color: '#7C6FF7' },
                  { label: 'Scans ce mois',     used: limits.remaining.monthUsed, max: limits.remaining.monthMax, color: '#4ECDC4' },
                  { label: 'Scans simultanés',  used: limits.remaining.runningScans, max: limits.remaining.maxConcurrent, color: '#FFB347' },
                ].map(({ label, used, max, color }) => (
                  <div key={label}>
                    <div className="flex justify-between text-xs mb-1">
                      <span style={{ color: '#6B6B8A' }}>{label}</span>
                      <span className="font-mono font-bold" style={{ color: used >= max ? '#FF6B6B' : color }}>
                        {used}/{max}
                      </span>
                    </div>
                    <div className="w-full rounded-full h-2" style={{ background: '#F0EEFF' }}>
                      <div className="h-2 rounded-full"
                           style={{ width: `${max > 0 ? Math.min(100, (used / max) * 100) : 0}%`, background: used >= max ? '#FF6B6B' : color }} />
                    </div>
                  </div>
                ))}
                <div className="pt-2 grid grid-cols-2 gap-2 text-xs" style={{ borderTop: '1px solid #F0EEFF' }}>
                  {[
                    ['Deep Scan', limits.permissions.canUseDeepScan],
                    ['Modules offensifs', limits.permissions.canUseOffensiveModules],
                    ['Rapports PDF', limits.permissions.canGenerateReports],
                    ['Export données', limits.permissions.canExportData],
                  ].map(([label, val]) => (
                    <div key={String(label)} className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full" style={{ background: val ? '#4ECDC4' : '#E5E7EB' }} />
                      <span style={{ color: val ? '#1C1C2E' : '#9CA3AF' }}>{String(label)}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs" style={{ color: '#6B6B8A' }}>Chargement…</p>
            )}
          </div>

          {/* Mes profils */}
          <div className="bg-white rounded-2xl p-5" style={{ border: '1px solid #EDE8FF' }}>
            <div className="flex items-center justify-between mb-4">
              <SectionTitle icon={BookmarkIcon} title="Mes profils de scan" />
              <span className="text-xs font-mono font-bold" style={{ color: '#7C6FF7' }}>
                {scanProfiles.length}
              </span>
            </div>
            <div className="space-y-2">
              {scanProfiles.map(p => (
                <div key={p.id}>
                  {editProfileId === p.id ? (
                    <div className="rounded-xl p-3 space-y-2" style={{ border: '1.5px solid #7C6FF7', background: '#F8F6FF' }}>
                      <input value={editName} onChange={e => setEditName(e.target.value)}
                             className="w-full text-sm px-3 py-1.5 rounded-lg outline-none"
                             style={{ border: '1px solid #EDE8FF', background: '#fff' }} />
                      <input value={editDesc} onChange={e => setEditDesc(e.target.value)}
                             placeholder="Description (optionnel)"
                             className="w-full text-xs px-3 py-1.5 rounded-lg outline-none"
                             style={{ border: '1px solid #EDE8FF', background: '#fff' }} />
                      <div className="flex gap-2">
                        <button onClick={() => updateProfile({ id: p.id, name: editName, description: editDesc || undefined })}
                                className="px-3 py-1.5 rounded-lg text-xs font-semibold text-white"
                                style={{ background: '#7C6FF7' }}>
                          Sauvegarder
                        </button>
                        <button onClick={() => setEditProfileId(null)}
                                className="px-3 py-1.5 rounded-lg text-xs font-semibold"
                                style={{ color: '#6B6B8A', border: '1px solid #EDE8FF' }}>
                          Annuler
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center gap-3 rounded-xl px-3 py-2.5 group"
                         style={{ border: '1px solid #F0EEFF', background: p.isDefault ? '#F8F6FF' : 'transparent' }}>
                      <BookmarkIcon size={13} style={{ color: p.isDefault ? '#7C6FF7' : '#9CA3AF', flexShrink: 0 }} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold text-navy truncate">{p.name}</p>
                        <p className="text-[11px]" style={{ color: '#6B6B8A' }}>
                          {p.modules.length} modules{p.description ? ` · ${p.description}` : ''}
                        </p>
                      </div>
                      <button onClick={() => { setEditProfileId(p.id); setEditName(p.name); setEditDesc(p.description ?? ''); }}
                              className="opacity-0 group-hover:opacity-100 p-1 rounded text-xs"
                              style={{ color: '#7C6FF7' }}>
                        <Plus size={12} />
                      </button>
                      {!p.isDefault && (
                        <button onClick={() => deleteProfile(p.id)}
                                className="opacity-0 group-hover:opacity-100 p-1 rounded"
                                style={{ color: '#FF6B6B' }}>
                          <Trash2 size={12} />
                        </button>
                      )}
                    </div>
                  )}
                </div>
              ))}
              {scanProfiles.length === 0 && (
                <p className="text-xs text-center py-4" style={{ color: '#9CA3AF' }}>
                  Aucun profil — créez-en un depuis la page Nouveau scan
                </p>
              )}
            </div>
          </div>

          {/* Historique récent */}
          <div className="bg-white rounded-2xl p-5" style={{ border: '1px solid #EDE8FF' }}>
            <div className="flex items-center justify-between mb-4">
              <SectionTitle icon={BarChart2} title="Historique des scans" />
              <span className="text-xs" style={{ color: '#6B6B8A' }}>{totalScans} total</span>
            </div>
            <div className="space-y-2">
              {recentScans.slice(0, 6).map(s => (
                <div key={s.id} className="flex items-center gap-3 text-xs">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ background: SEV_COLORS[s.status] ?? '#9CA3AF' }} />
                  <div className="flex-1 min-w-0">
                    <p className="font-mono text-navy truncate">{s.targetUrl.replace(/^https?:\/\//, '')}</p>
                    <p style={{ color: '#6B6B8A' }}>
                      {new Date(s.createdAt).toLocaleDateString('fr-FR')} · {SEV_LABELS[s.status]}
                    </p>
                  </div>
                </div>
              ))}
              {recentScans.length === 0 && (
                <p className="text-xs text-center py-4" style={{ color: '#9CA3AF' }}>Aucun scan</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
}
