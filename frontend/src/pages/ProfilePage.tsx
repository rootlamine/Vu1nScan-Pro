import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { User, Lock, Shield } from 'lucide-react';
import { Layout, TopBar } from '@/components/ui/Layout';
import { Toast }  from '@/components/ui/Toast';
import { useAuth } from '@/hooks/useAuth';
import api from '@/services/api';

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

export default function ProfilePage() {
  const { user, login, token } = useAuth();
  const [toast, setToast] = useState<{ msg: string; type: 'success'|'error' } | null>(null);

  const profileForm = useForm<ProfileForm>({
    resolver: zodResolver(profileSchema),
    defaultValues: { username: user?.username ?? '', email: user?.email ?? '' },
  });
  const passwordForm = useForm<PasswordForm>({ resolver: zodResolver(passwordSchema) });

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

  return (
    <Layout>
      {toast && <Toast message={toast.msg} type={toast.type} onClose={() => setToast(null)} />}
      <TopBar title="Mon profil" subtitle="Gérer vos informations et sécurité du compte" />

      <div className="px-8 py-6 max-w-[560px]">
        {/* Avatar */}
        <div className="bg-white rounded-2xl p-5 mb-5 flex items-center gap-4"
             style={{ border: '1px solid #EDE8FF' }}>
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
        <div className="bg-white rounded-2xl p-6 mb-5" style={{ border: '1px solid #EDE8FF' }}>
          <h2 className="font-semibold text-navy mb-4 flex items-center gap-2 text-sm">
            <User size={16} className="text-violet" /> Informations générales
          </h2>
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
            <button type="submit" disabled={profileForm.formState.isSubmitting}
                    className="w-full py-3 rounded-xl font-semibold text-sm text-white disabled:opacity-50"
                    style={{ background: '#7C6FF7' }}>
              {profileForm.formState.isSubmitting ? 'Enregistrement…' : 'Enregistrer'}
            </button>
          </form>
        </div>

        {/* Mot de passe */}
        <div className="bg-white rounded-2xl p-6" style={{ border: '1px solid #EDE8FF' }}>
          <h2 className="font-semibold text-navy mb-4 flex items-center gap-2 text-sm">
            <Lock size={16} className="text-violet" /> Changer le mot de passe
          </h2>
          <form onSubmit={passwordForm.handleSubmit(onPasswordSubmit)} className="space-y-4">
            {(['currentPassword', 'newPassword', 'confirm'] as const).map(field => {
              const labels = { currentPassword: 'Mot de passe actuel', newPassword: 'Nouveau mot de passe', confirm: 'Confirmer' };
              const placeholders = { currentPassword: '••••••••', newPassword: 'Min. 8 car., maj., min., chiffre', confirm: '••••••••' };
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
    </Layout>
  );
}
