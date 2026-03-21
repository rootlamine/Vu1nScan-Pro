import { useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Link, useNavigate } from 'react-router-dom';
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
    .regex(/\d/, 'Doit contenir un chiffre'),
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

  return (
    <div className="min-h-screen flex items-center justify-center bg-cream px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-navy mb-4">
            <span className="text-3xl">🛡</span>
          </div>
          <h1 className="text-2xl font-bold text-navy">Créer un compte</h1>
          <p className="text-gray-500 mt-1">Rejoignez VulnScan Pro</p>
        </div>

        <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-8">
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            {errors.root && (
              <div className="bg-red-50 text-coral text-sm rounded-lg p-3 text-center">
                {errors.root.message}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-navy mb-1">Nom d'utilisateur</label>
              <input
                {...register('username')}
                placeholder="alice"
                className="w-full px-4 py-2.5 rounded-xl border border-gray-200 focus:outline-none focus:border-violet focus:ring-1 focus:ring-violet text-sm"
              />
              {errors.username && <p className="text-coral text-xs mt-1">{errors.username.message}</p>}
            </div>

            <div>
              <label className="block text-sm font-medium text-navy mb-1">Email</label>
              <input
                {...register('email')}
                type="email"
                placeholder="alice@exemple.com"
                className="w-full px-4 py-2.5 rounded-xl border border-gray-200 focus:outline-none focus:border-violet focus:ring-1 focus:ring-violet text-sm"
              />
              {errors.email && <p className="text-coral text-xs mt-1">{errors.email.message}</p>}
            </div>

            <div>
              <label className="block text-sm font-medium text-navy mb-1">Mot de passe</label>
              <input
                {...register('password')}
                type="password"
                placeholder="Min. 8 car., maj., min., chiffre"
                className="w-full px-4 py-2.5 rounded-xl border border-gray-200 focus:outline-none focus:border-violet focus:ring-1 focus:ring-violet text-sm"
              />
              {errors.password && <p className="text-coral text-xs mt-1">{errors.password.message}</p>}
            </div>

            <div>
              <label className="block text-sm font-medium text-navy mb-1">Confirmer le mot de passe</label>
              <input
                {...register('confirm')}
                type="password"
                placeholder="••••••••"
                className="w-full px-4 py-2.5 rounded-xl border border-gray-200 focus:outline-none focus:border-violet focus:ring-1 focus:ring-violet text-sm"
              />
              {errors.confirm && <p className="text-coral text-xs mt-1">{errors.confirm.message}</p>}
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 bg-coral text-white font-semibold rounded-xl hover:bg-opacity-90 transition disabled:opacity-50"
            >
              {isSubmitting ? 'Création...' : 'Créer mon compte'}
            </button>
          </form>

          <p className="text-center text-sm text-gray-500 mt-6">
            Déjà un compte ?{' '}
            <Link to="/login" className="text-violet font-medium hover:underline">
              Se connecter
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
