import React, { useEffect, useState } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { Spinner } from './components/ui';
import LoginPage from './pages/LoginPage';
import ChangePasswordPage from './pages/ChangePasswordPage';
import DashboardPage from './pages/DashboardPage';
import AdminPage from './pages/AdminPage';
import OverviewPage from './pages/OverviewPage';
import NodesPage from './pages/NodesPage';
import ApiKeysPage from './pages/ApiKeysPage';
import ApiKeyFormPage from './pages/apikeys/ApiKeyFormPage';
import CommandPalette from './components/CommandPalette';
import ShortcutsHelp from './components/ShortcutsHelp';
import { ConfirmProvider } from './components/ConfirmDialog';
import { useGlobalShortcuts } from './hooks/useGlobalShortcuts';
import { useTheme } from './components/ThemeProvider';
import { endSession, getMe, listNamespaces, tokenExpiresAt, tokenIdleSeconds, User } from './services/api';
import { isIdle, noteActivity } from './utils/session';

const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const { setMode } = useTheme();
  useGlobalShortcuts({ isAdmin: Boolean(user?.isAdmin), setTheme: setMode });

  const refreshUser = async () => {
    try {
      const data = await getMe();
      setUser(data.user);
    } catch (error) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (localStorage.getItem('authToken')) {
      void refreshUser();
    } else {
      setLoading(false);
    }
  }, []);

  // Back to the sign-in page after the inactivity timeout, even on a screen
  // that sends no requests (its polls are not activity). Polled, so a laptop
  // waking from sleep is caught too. A token from before the inactivity
  // timeout carries no idle claim: it ends at its expiry, as it used to.
  useEffect(() => {
    if (!user) return;
    const timer = window.setInterval(() => {
      const idle = tokenIdleSeconds();
      const exp = tokenExpiresAt();
      if (idle ? isIdle(idle) : exp !== null && Date.now() >= exp) endSession();
    }, 15_000);
    // Clicks and keys are activity; while they go on without requests (typing
    // in a shell), one request a minute keeps the server's deadline moving.
    let lastPing = Date.now();
    const onInput = () => {
      noteActivity();
      if (Date.now() - lastPing < 60_000) return;
      lastPing = Date.now();
      void getMe().catch(() => undefined);
    };
    // Signed out in another tab: this one follows.
    const onStorage = (e: StorageEvent) => {
      if (e.key === 'authToken' && !e.newValue) endSession();
    };
    window.addEventListener('pointerdown', onInput, true);
    window.addEventListener('keydown', onInput, true);
    window.addEventListener('storage', onStorage);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener('pointerdown', onInput, true);
      window.removeEventListener('keydown', onInput, true);
      window.removeEventListener('storage', onStorage);
    };
  }, [user]);

  useEffect(() => {
    if (!user) return;
    listNamespaces(true)
      .then((r) => setNamespaces(r.namespaces ?? []))
      .catch(() => setNamespaces([]));
  }, [user]);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner size="lg" />
      </div>
    );
  }

  return (
    <ConfirmProvider>
      <Routes>
        <Route path="/login" element={<LoginPage onLogin={refreshUser} />} />
        <Route
          path="/change-password"
          element={user ? <ChangePasswordPage onChanged={refreshUser} /> : <Navigate to="/login" />}
        />
        <Route
          path="/"
          element={user ? <DashboardPage user={user} /> : <Navigate to="/login" />}
        />
        <Route
          path="/overview"
          element={user ? user.isAdmin ? <OverviewPage user={user} /> : <Navigate to="/" /> : <Navigate to="/login" />}
        />
        <Route
          path="/nodes"
          element={user ? user.isAdmin ? <NodesPage user={user} /> : <Navigate to="/" /> : <Navigate to="/login" />}
        />
        <Route
          path="/admin"
          element={user ? <AdminPage user={user} /> : <Navigate to="/login" />}
        />
        <Route path="/account/api-keys" element={user ? <ApiKeysPage user={user} /> : <Navigate to="/login" />} />
        <Route path="/account/api-keys/:id" element={user ? <ApiKeyFormPage user={user} /> : <Navigate to="/login" />} />
      </Routes>
      {user && <CommandPalette user={user} namespaces={namespaces} />}
      <ShortcutsHelp />
    </ConfirmProvider>
  );
};

export default App;
