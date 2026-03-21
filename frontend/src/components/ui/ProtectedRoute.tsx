import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';

export function ProtectedRoute() {
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    // Attend la restauration depuis localStorage (montage initial)
    const storedToken = localStorage.getItem('token');
    if (storedToken) return null; // bref instant de chargement
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
