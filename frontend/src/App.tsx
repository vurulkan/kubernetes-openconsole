import React, { Suspense, lazy, useEffect, useState } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { Spinner } from './components/ui';
import LoginPage from './pages/LoginPage';
import ChangePasswordPage from './pages/ChangePasswordPage';

// Each screen is its own chunk, loaded when first opened.
const DashboardPage = lazy(() => import('./pages/DashboardPage'));
const AdminPage = lazy(() => import('./pages/AdminPage'));
const OverviewPage = lazy(() => import('./pages/OverviewPage'));
const NodesPage = lazy(() => import('./pages/NodesPage'));
const ApiKeysPage = lazy(() => import('./pages/ApiKeysPage'));
const ApiKeyFormPage = lazy(() => import('./pages/apikeys/ApiKeyFormPage'));
const TwoFactorPage = lazy(() => import('./pages/TwoFactorPage'));
const TwoFactorEnroll = lazy(() => import('./pages/account/TwoFactorEnroll'));
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
      setUser({ ...data.user, twoFactor: data.twoFactor });
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
    // in a shell), a request every minute (a quarter of a shorter timeout)
    // keeps the server's deadline moving.
    let lastPing = Date.now();
    const pingEvery = Math.min(60_000, (tokenIdleSeconds() ?? 3600) * 250);
    const onInput = () => {
      noteActivity();
      if (Date.now() - lastPing < pingEvery) return;
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

  // A session that must set up two-factor authentication reaches nothing else.
  const enroll = Boolean(user?.twoFactor?.enroll);

  useEffect(() => {
    if (!user || enroll) return;
    listNamespaces(true)
      .then((r) => setNamespaces(r.namespaces ?? []))
      .catch(() => setNamespaces([]));
  }, [user, enroll]);

  const pageLoading = (
    <div className="flex min-h-screen items-center justify-center">
      <Spinner size="lg" />
    </div>
  );
  if (loading) return pageLoading;
  // The password change comes first (it signs out); then the blocking set-up.
  if (user && enroll && !user.mustChangePassword) {
    return (
      <Suspense fallback={pageLoading}>
        <TwoFactorEnroll onDone={() => void refreshUser()} />
      </Suspense>
    );
  }

  return (
    <ConfirmProvider>
      <Suspense fallback={pageLoading}>
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
        <Route path="/account/two-factor" element={user ? <TwoFactorPage user={user} onChanged={refreshUser} /> : <Navigate to="/login" />} />
      </Routes>
      </Suspense>
      {user && <CommandPalette user={user} namespaces={namespaces} />}
      <ShortcutsHelp />
    </ConfirmProvider>
  );
};

export default App;
