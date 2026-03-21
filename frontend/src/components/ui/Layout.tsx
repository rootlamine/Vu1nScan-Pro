import React from 'react';
import { NavLink, useNavigate, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, ScanLine, ShieldAlert, FileText,
  Users, Cpu, BarChart3, LogOut, Plus, type LucideIcon,
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';

/* ── types ────────────────────────────────────────────────────────── */
interface NavItem {
  to:        string;
  label:     string;
  icon:      LucideIcon;
  badge?:    number;
  adminOnly?: boolean;
}

const PRINCIPAL: NavItem[] = [
  { to: '/dashboard',       label: 'Dashboard',       icon: LayoutDashboard },
  { to: '/scans',           label: 'Mes scans',        icon: ScanLine,   badge: 0 },
  { to: '/vulnerabilities', label: 'Vulnérabilités',   icon: ShieldAlert },
  { to: '/reports',         label: 'Rapports',         icon: FileText    },
];

const ADMIN_NAV: NavItem[] = [
  { to: '/admin',       label: 'Utilisateurs', icon: Users,    adminOnly: true },
  { to: '/admin/modules', label: 'Modules',   icon: Cpu,      adminOnly: true },
  { to: '/admin/stats',   label: 'Statistiques', icon: BarChart3, adminOnly: true },
];

/* ── SideLink ─────────────────────────────────────────────────────── */
function SideLink({ item }: { item: NavItem }) {
  const location = useLocation();
  // Match admin tabs
  const isActive = location.pathname === item.to ||
    (item.to === '/admin' && location.pathname.startsWith('/admin') &&
     !location.pathname.includes('/modules') && !location.pathname.includes('/stats'));

  return (
    <NavLink
      to={item.to}
      end={item.to !== '/admin'}
      className="flex items-center gap-2.5 px-3 py-2 rounded-xl text-sm font-medium transition-all relative"
      style={({ isActive: navActive }) => {
        const active = navActive || isActive;
        return active
          ? { background: 'rgba(124,111,247,.18)', color: '#fff', border: '1px solid rgba(124,111,247,.25)' }
          : { color: 'rgba(255,255,255,.55)', border: '1px solid transparent' };
      }}
    >
      <item.icon size={16} />
      <span className="flex-1">{item.label}</span>
      {item.badge != null && item.badge > 0 && (
        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full min-w-[18px] text-center"
              style={{ background: '#FFB347', color: '#fff' }}>
          {item.badge}
        </span>
      )}
    </NavLink>
  );
}

/* ── Layout ───────────────────────────────────────────────────────── */
interface Props { children: React.ReactNode }

export function Layout({ children }: Props) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => { logout(); navigate('/login', { replace: true }); };
  const initials = (user?.username ?? 'U').slice(0, 2).toUpperCase();

  return (
    <div className="flex min-h-screen">
      {/* ── Sidebar ──────────────────────────────────────────────── */}
      <aside
        className="w-[210px] shrink-0 fixed inset-y-0 left-0 z-30 flex flex-col overflow-hidden"
        style={{ background: '#1A1A2E' }}
      >
        {/* Fond décoratif cercles */}
        <div className="absolute bottom-0 left-0 right-0 h-64 pointer-events-none overflow-hidden">
          <div className="absolute" style={{
            width: 220, height: 220, borderRadius: '50%',
            background: 'radial-gradient(circle, rgba(124,111,247,.12) 0%, transparent 70%)',
            bottom: -60, left: -40,
          }} />
        </div>

        {/* Logo */}
        <div className="relative z-10 px-5 pt-5 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
                 style={{ background: '#FF6B6B' }}>
              <ShieldAlert size={16} color="#fff" />
            </div>
            <div className="font-bold text-sm leading-tight">
              <span style={{ color: '#FF6B6B' }}>Vu</span>
              <span className="text-white">1nScan </span>
              <span className="text-white">Pro</span>
            </div>
          </div>
        </div>

        {/* PRINCIPAL */}
        <nav className="relative z-10 px-3 flex-1 overflow-y-auto">
          <p className="text-[10px] font-bold tracking-widest px-3 mb-2 mt-1"
             style={{ color: 'rgba(255,255,255,.35)' }}>
            PRINCIPAL
          </p>
          <div className="space-y-0.5">
            {PRINCIPAL.map(item => <SideLink key={item.to} item={item} />)}
          </div>

          {user?.role === 'ADMIN' && (
            <>
              <p className="text-[10px] font-bold tracking-widest px-3 mb-2 mt-5"
                 style={{ color: 'rgba(255,255,255,.35)' }}>
                ADMINISTRATION
              </p>
              <div className="space-y-0.5">
                {ADMIN_NAV.map(item => <SideLink key={item.to} item={item} />)}
              </div>
            </>
          )}
        </nav>

        {/* Utilisateur */}
        <div className="relative z-10 px-3 pb-4 pt-3"
             style={{ borderTop: '1px solid rgba(255,255,255,.07)' }}>
          <div className="flex items-center gap-2.5 px-2 mb-2">
            <div className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold shrink-0"
                 style={{ background: '#FF6B6B', color: '#fff' }}>
              {initials}
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-white text-xs font-semibold truncate">{user?.username}</p>
              <p className="text-[10px] truncate" style={{ color: 'rgba(255,255,255,.4)' }}>
                {user?.role === 'ADMIN' ? 'Administrateur' : 'Utilisateur'}
              </p>
            </div>
            <button
              onClick={handleLogout}
              className="shrink-0 transition-all"
              style={{ color: 'rgba(255,255,255,.4)' }}
              title="Déconnexion"
            >
              <LogOut size={15} />
            </button>
          </div>
        </div>
      </aside>

      {/* ── Main ─────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-h-screen" style={{ marginLeft: 210 }}>
        {children}
      </div>
    </div>
  );
}

/* ── TopBar ───────────────────────────────────────────────────────── */
export function TopBar({
  title, subtitle, action,
}: {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
}) {
  const navigate = useNavigate();
  return (
    <div className="flex items-center justify-between px-8 py-5"
         style={{ borderBottom: '1px solid #EDE8FF', background: '#fff' }}>
      <div>
        <h1 className="text-xl font-bold text-navy">{title}</h1>
        {subtitle && <p className="text-xs mt-0.5" style={{ color: '#6B6B8A' }}>{subtitle}</p>}
      </div>
      <div className="flex items-center gap-3">
        {action}
        <button
          onClick={() => navigate('/scans/new')}
          className="flex items-center gap-2 px-4 py-2 rounded-xl font-semibold text-sm text-white transition-all"
          style={{ background: '#FF6B6B' }}
        >
          <Plus size={16} />
          Nouveau scan
        </button>
      </div>
    </div>
  );
}
