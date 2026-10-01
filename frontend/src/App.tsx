import React, { useEffect, useState } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { Spinner } from './components/ui';
import LoginPage from './pages/LoginPage';
import ChangePasswordPage from './pages/ChangePasswordPage';
import DashboardPage from './pages/DashboardPage';
import AdminPage from './pages/AdminPage';
import CommandPalette from './components/CommandPalette';
import ShortcutsHelp from './components/ShortcutsHelp';
import { ConfirmProvider } from './components/ConfirmDialog';
import { useGlobalShortcuts } from './hooks/useGlobalShortcuts';
import { useTheme } from './components/ThemeProvider';
import { getMe, listNamespaces, User } from './services/api';

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

  useEffect(() => {
    if (!user) return;
    listNamespaces()
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
          path="/admin"
          element={user ? <AdminPage user={user} /> : <Navigate to="/login" />}
        />
      </Routes>
      {user && <CommandPalette user={user} namespaces={namespaces} />}
      <ShortcutsHelp />
    </ConfirmProvider>
  );
};

export default App;
