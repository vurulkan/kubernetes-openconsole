import React, { useState } from 'react';
import { Menu, X } from 'lucide-react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Button } from './ui';
import { User } from '../services/api';

type Props = {
  user: User;
  namespaces: string[];
  activeNamespace: string | null;
  onNamespaceChange: (value: string) => void;
  namespaceSearch?: string;
  onNamespaceSearchChange?: (value: string) => void;
  children: React.ReactNode;
};

const Layout: React.FC<Props> = ({
  user,
  namespaces,
  activeNamespace,
  onNamespaceChange,
  namespaceSearch = '',
  onNamespaceSearchChange,
  children,
}) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const filteredNamespaces = namespaceSearch
    ? namespaces.filter((ns) => ns.toLowerCase().includes(namespaceSearch.trim().toLowerCase()))
    : namespaces;

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    navigate('/login');
  };

  const closeSidebar = () => setSidebarOpen(false);

  return (
    <div className="min-h-screen bg-slate-50 font-sans">
      {/* ── Top header ─────────────────────────────────────────────── */}
      <header className="fixed left-0 right-0 top-0 z-30 flex h-14 items-center gap-3 border-b border-gray-200 bg-white px-4 shadow-sm">
        <button
          className="rounded-lg p-1.5 text-gray-500 hover:bg-gray-100 focus:outline-none md:hidden"
          onClick={() => setSidebarOpen(true)}
          aria-label="Open sidebar"
        >
          <Menu size={20} />
        </button>

        <span className="text-base font-semibold text-gray-900">Kubernetes OpenConsole</span>

        <div className="ml-auto flex items-center gap-2">
          <span className="hidden text-sm text-gray-500 sm:block">{user.username}</span>
          {location.pathname.startsWith('/admin') && (
            <Button variant="outline" size="sm" onClick={() => navigate('/')}>
              Dashboard
            </Button>
          )}
          {user.isAdmin && !location.pathname.startsWith('/admin') && (
            <Button variant="outline" size="sm" onClick={() => navigate('/admin')}>
              Admin
            </Button>
          )}
          <Button variant="primary" size="sm" onClick={handleLogout}>
            Sign out
          </Button>
        </div>
      </header>

      {/* ── Mobile overlay ─────────────────────────────────────────── */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={closeSidebar}
        />
      )}

      {/* ── Sidebar ────────────────────────────────────────────────── */}
      <aside
        className={`fixed bottom-0 left-0 top-0 z-50 flex w-[260px] flex-col bg-slate-900 text-white transition-transform duration-200 md:top-14 md:translate-x-0 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        }`}
      >
        {/* Mobile header inside sidebar */}
        <div className="flex h-14 items-center justify-between border-b border-slate-700 px-4 md:hidden">
          <span className="text-sm font-semibold">Kubernetes OpenConsole</span>
          <button
            onClick={closeSidebar}
            className="rounded p-1 text-slate-300 hover:text-white focus:outline-none"
          >
            <X size={18} />
          </button>
        </div>

        <div className="flex flex-1 flex-col gap-3 overflow-auto p-4">
          {onNamespaceSearchChange && (
            <input
              type="text"
              placeholder="Search namespaces..."
              value={namespaceSearch}
              onChange={(e) => onNamespaceSearchChange(e.target.value)}
              className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white placeholder:text-slate-400 focus:border-slate-500 focus:outline-none"
            />
          )}

          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wider text-slate-400">
              Namespaces
            </p>
            <div className="h-px bg-slate-700" />
          </div>

          <div className="flex flex-col gap-0.5">
            {filteredNamespaces.map((ns) => (
              <button
                key={ns}
                onClick={() => {
                  onNamespaceChange(ns);
                  closeSidebar();
                }}
                className={`rounded-lg px-3 py-2 text-left text-sm transition-colors ${
                  activeNamespace === ns
                    ? 'bg-blue-700 text-white'
                    : 'text-slate-200 hover:bg-slate-800'
                }`}
              >
                {ns}
              </button>
            ))}
          </div>
        </div>
      </aside>

      {/* ── Main content ───────────────────────────────────────────── */}
      <main className="min-h-screen pt-14 md:pl-[260px]">
        <div className="p-6">{children}</div>
      </main>
    </div>
  );
};

export default Layout;
