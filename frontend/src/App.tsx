import React, { useEffect, useState } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { ThemeProvider, createTheme, CssBaseline, CircularProgress, Box } from '@mui/material';
import LoginPage from './pages/LoginPage';
import ChangePasswordPage from './pages/ChangePasswordPage';
import DashboardPage from './pages/DashboardPage';
import AdminPage from './pages/AdminPage';
import { getMe, User } from './services/api';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: { main: '#174bd2' },
    background: { default: '#f5f7fb' }
  },
  typography: {
    fontFamily: 'Inter, system-ui, sans-serif'
  }
});

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
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Box display="flex" alignItems="center" justifyContent="center" minHeight="100vh">
          <CircularProgress />
        </Box>
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
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
    </ThemeProvider>
  );
};

export default App;
