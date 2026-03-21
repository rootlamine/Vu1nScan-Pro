import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Mail, Lock, User, ArrowRight } from 'lucide-react';
import api from '@/services/api';
import { useAuth } from '@/hooks/useAuth';

const schema = z.object({
  username: z.string().min(3, 'Minimum 3 caractères').max(30),
  email:    z.string().email('Email invalide'),
  password: z
    .string()
    .min(8, 'Minimum 8 caractères')
    .regex(/[A-Z]/, 'Doit contenir une majuscule')
    .regex(/[a-z]/, 'Doit contenir une minuscule')
    .regex(/\d/,    'Doit contenir un chiffre'),
  confirm: z.string(),
}).refine(d => d.password === d.confirm, {
  message: 'Les mots de passe ne correspondent pas',
  path: ['confirm'],
});

type FormData = z.infer<typeof schema>;

export default function RegisterPage() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated) navigate('/dashboard', { replace: true });
  }, [isAuthenticated, navigate]);

  const {
    register, handleSubmit,
    formState: { errors, isSubmitting },
    setError,
  } = useForm<FormData>({ resolver: zodResolver(schema) });

  const onSubmit = async (data: FormData) => {
    try {
      const res = await api.post('/auth/register', {
        username: data.username,
        email:    data.email,
        password: data.password,
      });
      login(res.data.data.token, res.data.data.user);
      navigate('/dashboard', { replace: true });
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })
        ?.response?.data?.message ?? "Erreur lors de l'inscription";
      setError('root', { message: msg });
    }
  };

  const inputCls = (hasErr: boolean) => ({
    border:     hasErr ? '1.5px solid #FF6B6B' : '1.5px solid #EDE8FF',
    background: '#FAFAFA',
  });
  const focusIn  = (e: React.FocusEvent<HTMLInputElement>) => {
    e.currentTarget.style.borderColor = '#7C6FF7';
    e.currentTarget.style.boxShadow   = '0 0 0 3px rgba(124,111,247,.12)';
  };
  const focusOut = (hasErr: boolean) => (e: React.FocusEvent<HTMLInputElement>) => {
    e.currentTarget.style.borderColor = hasErr ? '#FF6B6B' : '#EDE8FF';
    e.currentTarget.style.boxShadow   = 'none';
  };

  return (
    <div className="min-h-screen flex" style={{ fontFamily: 'Sora, sans-serif' }}>

      {/* ── Colonne gauche ──────────────────────────────────────────── */}
      <div className="hidden lg:flex lg:w-1/2 flex-col relative overflow-hidden"
           style={{ background: '#1C1C2E' }}>
        <div className="absolute" style={{ width: 400, height: 400, borderRadius: '50%', border: '1px solid rgba(124,111,247,.15)', top: -100, left: -100 }} />
        <div className="absolute" style={{ width: 600, height: 600, borderRadius: '50%', border: '1px solid rgba(124,111,247,.08)', top: -200, left: -200 }} />
        <div className="absolute" style={{ width: 300, height: 300, borderRadius: '50%', background: 'rgba(124,111,247,.06)', bottom: 80, right: -80 }} />

        <div className="relative z-10 flex flex-col h-full px-12 py-12">
          <div className="flex items-center gap-3 mb-auto">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                 style={{ background: 'rgba(124,111,247,.25)' }}>
              <Shield size={20} className="text-violet" />
            </div>
            <span className="text-white font-bold text-lg">VulnScan Pro</span>
          </div>

          <div className="mb-12">
            <h1 className="text-4xl font-bold text-white leading-tight mb-4">
              Rejoignez<br />
              <span style={{ color: '#7C6FF7' }}>VulnScan Pro</span><br />
              dès aujourd'hui.
            </h1>
            <p className="text-base" style={{ color: 'rgba(255,255,255,.55)', lineHeight: 1.7 }}>
              Créez votre compte gratuit et commencez<br />
              à scanner vos applications en quelques minutes.
            </p>
          </div>

          <div className="grid grid-cols-3 gap-4">
            {[
              { value: '19',   label: 'Modules actifs' },
              { value: '100%', label: 'Open source'    },
              { value: 'PDF',  label: 'Rapports'       },
            ].map(s => (
              <div key={s.label} className="rounded-xl p-4"
                   style={{ background: 'rgba(255,255,255,.05)', border: '1px solid rgba(255,255,255,.08)' }}>
                <p className="font-mono font-bold text-xl text-white">{s.value}</p>
                <p className="text-xs mt-1" style={{ color: 'rgba(255,255,255,.45)' }}>{s.label}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Colonne droite ──────────────────────────────────────────── */}
      <div className="flex-1 flex items-center justify-center px-6 py-12 bg-white relative">
        <div className="absolute inset-0 pointer-events-none" style={{
          backgroundImage: 'linear-gradient(rgba(124,111,247,.04) 1px, transparent 1px), linear-gradient(90deg, rgba(124,111,247,.04) 1px, transparent 1px)',
          backgroundSize: '32px 32px',
        }} />

        <div className="relative z-10 w-full max-w-[400px]">
          <div className="lg:hidden flex items-center gap-3 mb-8">
            <div className="w-9 h-9 rounded-xl flex items-center justify-center" style={{ background: '#1C1C2E' }}>
              <Shield size={17} className="text-violet" />
            </div>
            <span className="font-bold text-navy text-lg">VulnScan Pro</span>
          </div>

          <h2 className="text-2xl font-bold text-navy mb-1">Créer un compte</h2>
          <p className="text-sm mb-7" style={{ color: '#6B6B8A' }}>
            Remplissez le formulaire pour rejoindre la plateforme
          </p>

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            {errors.root && (
              <div className="rounded-xl p-3 text-sm text-center"
                   style={{ background: '#FFF0F0', color: '#FF6B6B', border: '1px solid #FFD0D0' }}>
                {errors.root.message}
              </div>
            )}

            {/* Username */}
            <div>
              <label className="block text-sm font-semibold text-navy mb-1.5">Nom d'utilisateur</label>
              <div className="relative">
                <User size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
                <input
                  {...register('username')}
                  placeholder="alice"
                  className="w-full pl-10 pr-4 py-3 rounded-xl text-sm outline-none transition-all"
                  style={inputCls(!!errors.username)}
                  onFocus={focusIn}
                  onBlur={focusOut(!!errors.username)}
                />
              </div>
              {errors.username && <p className="text-xs mt-1" style={{ color: '#FF6B6B' }}>{errors.username.message}</p>}
            </div>

            {/* Email */}
            <div>
              <label className="block text-sm font-semibold text-navy mb-1.5">Email</label>
              <div className="relative">
                <Mail size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
                <input
                  {...register('email')}
                  type="email"
                  placeholder="alice@exemple.com"
                  className="w-full pl-10 pr-4 py-3 rounded-xl text-sm outline-none transition-all"
                  style={inputCls(!!errors.email)}
                  onFocus={focusIn}
                  onBlur={focusOut(!!errors.email)}
                />
              </div>
              {errors.email && <p className="text-xs mt-1" style={{ color: '#FF6B6B' }}>{errors.email.message}</p>}
            </div>

            {/* Password */}
            <div>
              <label className="block text-sm font-semibold text-navy mb-1.5">Mot de passe</label>
              <div className="relative">
                <Lock size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
                <input
                  {...register('password')}
                  type="password"
                  placeholder="Min. 8 car., maj., min., chiffre"
                  className="w-full pl-10 pr-4 py-3 rounded-xl text-sm outline-none transition-all"
                  style={inputCls(!!errors.password)}
                  onFocus={focusIn}
                  onBlur={focusOut(!!errors.password)}
                />
              </div>
              {errors.password && <p className="text-xs mt-1" style={{ color: '#FF6B6B' }}>{errors.password.message}</p>}
            </div>

            {/* Confirm */}
            <div>
              <label className="block text-sm font-semibold text-navy mb-1.5">Confirmer le mot de passe</label>
              <div className="relative">
                <Lock size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2" style={{ color: '#6B6B8A' }} />
                <input
                  {...register('confirm')}
                  type="password"
                  placeholder="••••••••"
                  className="w-full pl-10 pr-4 py-3 rounded-xl text-sm outline-none transition-all"
                  style={inputCls(!!errors.confirm)}
                  onFocus={focusIn}
                  onBlur={focusOut(!!errors.confirm)}
                />
              </div>
              {errors.confirm && <p className="text-xs mt-1" style={{ color: '#FF6B6B' }}>{errors.confirm.message}</p>}
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold text-sm text-white transition-all disabled:opacity-50"
              style={{ background: '#7C6FF7' }}
            >
              {isSubmitting ? 'Création…' : <> Créer mon compte <ArrowRight size={16} /> </>}
            </button>
          </form>

          <p className="text-center text-sm mt-6" style={{ color: '#6B6B8A' }}>
            Déjà un compte ?{' '}
            <Link to="/login" className="font-semibold" style={{ color: '#7C6FF7' }}>
              Se connecter
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
