import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Alert, Button, Input } from '../components/ui';
import { getAuthProviders, login, startAzureLogin } from '../services/api';

type Props = {
  onLogin: () => Promise<void>;
};

const LoginPage: React.FC<Props> = ({ onLogin }) => {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [logoUrl, setLogoUrl] = useState<string | null>(null);
  const [azureEnabled, setAzureEnabled] = useState(false);

  useEffect(() => {
    setLogoUrl('/api/customization/logo');
    const loadProviders = async () => {
      try {
        const providers = await getAuthProviders();
        setAzureEnabled(Boolean(providers.azureAdEnabled));
      } catch (err) {
        setAzureEnabled(false);
      }
    };
    void loadProviders();
  }, []);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const result = await login(username, password);
      localStorage.setItem('authToken', result.token);
      await onLogin();
      if (result.user.mustChangePassword) {
        navigate('/change-password');
      } else {
        navigate('/');
      }
    } catch (err) {
      setError('Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 p-4 font-sans">
      <div className="w-full max-w-sm rounded-xl border border-gray-200 bg-white p-8 shadow-sm">
        {logoUrl && (
          <div className="mb-6 flex justify-center overflow-hidden">
            <img
              src={logoUrl}
              alt="Organization logo"
              onError={() => setLogoUrl(null)}
              className="max-h-20 w-full max-w-full object-contain"
            />
          </div>
        )}

        <h1 className="mb-1 text-xl font-semibold text-gray-900">Kubernetes OpenConsole</h1>
        <p className="mb-6 text-sm text-gray-500">Sign in with your account.</p>

        {error && (
          <Alert severity="error" className="mb-4">
            {error}
          </Alert>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <Input
            label="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
          />
          <Input
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
          <Button type="submit" variant="primary" disabled={loading} className="w-full">
            {loading ? 'Signing in...' : 'Sign in'}
          </Button>
          {azureEnabled && (
            <Button type="button" variant="outline" onClick={startAzureLogin} className="w-full">
              Sign in with Microsoft
            </Button>
          )}
        </form>
      </div>
    </div>
  );
};

export default LoginPage;
