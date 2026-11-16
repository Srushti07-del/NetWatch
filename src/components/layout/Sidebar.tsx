/**
 * Sidebar.tsx
 * Collapsible left navigation sidebar.
 */
import {
  Activity,
  BarChart3,
  ChevronLeft,
  ChevronRight,
  Cpu,
  GitBranch,
  LayoutDashboard,
  Settings,
  Shield,
  Wifi,
} from 'lucide-react';
import { NavLink, useLocation } from 'react-router-dom';

interface NavItem {
  label: string;
  to: string;
  icon: React.ReactNode;
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Overview',         to: '/',                icon: <LayoutDashboard size={18} /> },
  { label: 'Live Traffic',     to: '/live-traffic',    icon: <Activity size={18} /> },
  { label: 'Devices',          to: '/devices',         icon: <Cpu size={18} /> },
  { label: 'Connections',      to: '/connections',     icon: <GitBranch size={18} /> },
  { label: 'Threat Detection', to: '/threats',         icon: <Shield size={18} /> },
  { label: 'Analytics',        to: '/analytics',       icon: <BarChart3 size={18} /> },
  { label: 'Settings',         to: '/settings',        icon: <Settings size={18} /> },
];

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const location = useLocation();

  return (
    <aside
      style={{
        width: collapsed ? 64 : 220,
        minWidth: collapsed ? 64 : 220,
        background: '#0D1726',
        borderRight: '1px solid #1E2D45',
        display: 'flex',
        flexDirection: 'column',
        transition: 'width 0.2s ease, min-width 0.2s ease',
        position: 'relative',
        zIndex: 10,
      }}
    >
      {/* Logo */}
      <div
        style={{
          height: 60,
          display: 'flex',
          alignItems: 'center',
          padding: collapsed ? '0 20px' : '0 20px',
          borderBottom: '1px solid #1E2D45',
          gap: 10,
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            width: 28,
            height: 28,
            background: 'linear-gradient(135deg, #42D6C5 0%, #3B82F6 100%)',
            borderRadius: 7,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}
        >
          <Wifi size={15} color="#0B1220" strokeWidth={2.5} />
        </div>
        {!collapsed && (
          <span
            style={{
              color: '#F1F5F9',
              fontWeight: 700,
              fontSize: 16,
              letterSpacing: '-0.3px',
              whiteSpace: 'nowrap',
            }}
          >
            NetWatch
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '12px 8px', overflowY: 'auto' }}>
        {NAV_ITEMS.map((item) => {
          const isActive =
            item.to === '/'
              ? location.pathname === '/'
              : location.pathname.startsWith(item.to);
          return (
            <NavLink
              key={item.to}
              to={item.to}
              title={collapsed ? item.label : undefined}
              style={({ isActive: routerActive }) => ({
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: collapsed ? '10px 14px' : '10px 12px',
                borderRadius: 8,
                marginBottom: 2,
                color: isActive || routerActive ? '#42D6C5' : '#94A3B8',
                background: isActive || routerActive ? 'rgba(66, 214, 197, 0.08)' : 'transparent',
                textDecoration: 'none',
                fontSize: 13.5,
                fontWeight: isActive || routerActive ? 600 : 400,
                transition: 'background 0.15s, color 0.15s',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                justifyContent: collapsed ? 'center' : 'flex-start',
              })}
            >
              <span style={{ flexShrink: 0 }}>{item.icon}</span>
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          );
        })}
      </nav>

      {/* Status indicator */}
      {!collapsed && (
        <div
          style={{
            padding: '12px 16px',
            borderTop: '1px solid #1E2D45',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <div
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: '#10B981',
              boxShadow: '0 0 6px rgba(16, 185, 129, 0.6)',
            }}
          />
          <span style={{ color: '#94A3B8', fontSize: 12 }}>Monitoring Active</span>
        </div>
      )}

      {/* Collapse toggle (desktop) */}
      <button
        onClick={onToggle}
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        style={{
          position: 'absolute',
          top: 18,
          right: -12,
          width: 24,
          height: 24,
          borderRadius: '50%',
          background: '#1E2D45',
          border: '1px solid #2a3f5f',
          color: '#94A3B8',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          cursor: 'pointer',
          zIndex: 20,
        }}
      >
        {collapsed ? <ChevronRight size={13} /> : <ChevronLeft size={13} />}
      </button>
    </aside>
  );
}
