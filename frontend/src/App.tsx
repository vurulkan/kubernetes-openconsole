import React, { useEffect, useState } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { Spinner } from './components/ui';
import LoginPage from './pages/LoginPage';
import ChangePasswordPage from './pages/ChangePasswordPage';
import DashboardPage from './pages/DashboardPage';
import AdminPage from './pages/AdminPage';
import { getMe, User } from './services/api';

const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

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

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <Spinner size="lg" />
      </div>
    );
  }

  return (
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
  );
};

export default App;
