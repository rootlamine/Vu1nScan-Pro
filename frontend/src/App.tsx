import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider }  from '@/hooks/useAuth';
import { ProtectedRoute } from '@/components/ui/ProtectedRoute';

import LoginPage          from '@/pages/LoginPage';
import RegisterPage       from '@/pages/RegisterPage';
import DashboardPage      from '@/pages/DashboardPage';
import ScansListPage      from '@/pages/ScansListPage';
import NewScanPage        from '@/pages/NewScanPage';
import ScanLivePage       from '@/pages/ScanLivePage';
import ScanResultsPage    from '@/pages/ScanResultsPage';
import ReportsPage        from '@/pages/ReportsPage';
import AdminPage          from '@/pages/AdminPage';
import ProfilePage        from '@/pages/ProfilePage';
import VulnerabilitiesPage from '@/pages/VulnerabilitiesPage';

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login"    element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />

        <Route element={<ProtectedRoute />}>
          <Route path="/"                    element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard"           element={<DashboardPage />} />
          <Route path="/scans"               element={<ScansListPage />} />
          <Route path="/scans/new"           element={<NewScanPage />} />
          <Route path="/scans/:id/live"      element={<ScanLivePage />} />
          <Route path="/scans/:id/results"   element={<ScanResultsPage />} />
          <Route path="/vulnerabilities"     element={<VulnerabilitiesPage />} />
          <Route path="/reports"             element={<ReportsPage />} />
          <Route path="/admin"               element={<AdminPage />} />
          <Route path="/admin/modules"       element={<AdminPage />} />
          <Route path="/admin/stats"         element={<AdminPage />} />
          <Route path="/profile"             element={<ProfilePage />} />
        </Route>

        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </AuthProvider>
  );
}
