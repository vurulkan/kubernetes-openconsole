import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Input } from '../components/ui';
import { getAuthProviders, login, startAzureLogin } from '../services/api';
import LocaleSwitcher from '../components/LocaleSwitcher';

type Props = {
  onLogin: () => Promise<void>;
};

const LoginPage: React.FC<Props> = ({ onLogin }) => {
  const navigate = useNavigate();
  const { t } = useTranslation();
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
      setError(t('login.failed'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center p-4 font-sans">
      <div className="pointer-events-none absolute inset-0 bg-brand-radial" aria-hidden="true" />

      {/* Locale switcher pinned top-right so a user whose browser is TR but
          lands on an EN-defaulted deploy can flip without logging in first. */}
      <div className="absolute right-4 top-4 z-10">
        <LocaleSwitcher />
      </div>

      <div className="relative grid w-full max-w-5xl grid-cols-1 overflow-hidden rounded-3xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-900/80 shadow-elevated backdrop-blur-sm md:grid-cols-[1.1fr,1fr]">
        {/* ── Brand side ────────────────────────────────────────────── */}
        <div className="relative hidden flex-col justify-between overflow-hidden bg-gradient-to-br from-slate-900 via-slate-900 to-brand-900 p-10 text-white md:flex">
          <div
            className="pointer-events-none absolute inset-0 opacity-70"
            style={{
              backgroundImage:
                'radial-gradient(600px 300px at 20% 10%, rgba(99,102,241,0.35), transparent 60%), radial-gradient(500px 300px at 90% 80%, rgba(16,185,129,0.25), transparent 60%)',
            }}
            aria-hidden="true"
          />
          <div className="relative">
            <div className="flex items-center gap-2.5">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-white dark:bg-slate-900/10 ring-1 ring-inset ring-white/15">
                <svg
                  viewBox="0 0 24 24"
                  className="h-5 w-5 text-white"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2.2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M12 2 3 7l9 5 9-5-9-5Z" />
                  <path d="M3 12l9 5 9-5" />
                  <path d="M3 17l9 5 9-5" />
                </svg>
              </div>
              <div className="flex flex-col leading-tight">
                <span className="text-sm font-semibold tracking-tight">Kubernetes OpenConsole</span>
                <span className="text-[10px] font-medium uppercase tracking-[0.18em] text-slate-400 dark:text-slate-500">
                  {t('login.tagline')}
                </span>
              </div>
            </div>
            <h2 className="mt-10 max-w-sm text-3xl font-semibold leading-tight tracking-tight">
              {t('login.headline')}
            </h2>
            <p className="mt-3 max-w-sm text-sm text-slate-300">
              {t('login.subheadline')}
            </p>
          </div>

          <div className="relative mt-8 grid grid-cols-3 gap-3 text-xs">
            {[
              { label: t('login.stats.namespaces'), value: t('login.stats.scoped') },
              { label: t('login.stats.workloads'), value: t('login.stats.live') },
              { label: t('login.stats.audit'), value: t('login.stats.always') },
            ].map((stat) => (
              <div
                key={stat.label}
                className="rounded-xl border border-white/10 bg-white dark:bg-slate-900/5 px-3 py-2.5 backdrop-blur-sm"
              >
                <div className="text-[10px] uppercase tracking-[0.14em] text-slate-400 dark:text-slate-500">
                  {stat.label}
                </div>
                <div className="mt-1 text-sm font-semibold text-white">{stat.value}</div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Form side ─────────────────────────────────────────────── */}
        <div className="flex flex-col justify-center p-8 sm:p-10">
          {logoUrl && (
            <div className="mb-6 flex justify-center overflow-hidden">
              <img
                src={logoUrl}
                alt="Organization logo"
                onError={() => setLogoUrl(null)}
                className="max-h-16 w-full max-w-full object-contain"
              />
            </div>
          )}

          <h1 className="text-xl font-semibold tracking-tight text-slate-900 dark:text-slate-100">{t('login.welcome')}</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{t('login.subtitle')}</p>

          {error && (
            <Alert severity="error" className="mt-5">
              {error}
            </Alert>
          )}

          <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-4">
            <Input
              label={t('login.username')}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              placeholder={t('login.usernamePlaceholder')}
            />
            <Input
              label={t('login.password')}
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              placeholder="••••••••"
            />
            <Button type="submit" variant="primary" disabled={loading} className="mt-1 w-full">
              {loading ? t('login.signingIn') : t('login.signIn')}
            </Button>
            {azureEnabled && (
              <>
                <div className="relative my-1 flex items-center">
                  <div className="h-px flex-1 bg-slate-200" />
                  <span className="px-3 text-[11px] font-medium uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    {t('login.or')}
                  </span>
                  <div className="h-px flex-1 bg-slate-200" />
                </div>
                <Button type="button" variant="outline" onClick={startAzureLogin} className="w-full">
                  <svg viewBox="0 0 23 23" className="h-4 w-4" aria-hidden="true">
                    <rect x="0" y="0" width="11" height="11" fill="#f25022" />
                    <rect x="12" y="0" width="11" height="11" fill="#7fba00" />
                    <rect x="0" y="12" width="11" height="11" fill="#00a4ef" />
                    <rect x="12" y="12" width="11" height="11" fill="#ffb900" />
                  </svg>
                  {t('login.signInMicrosoft')}
                </Button>
              </>
            )}
          </form>

          <div className="mt-6 flex items-center gap-2 text-[11px] text-slate-400 dark:text-slate-500">
            <ShieldCheck size={14} className="text-emerald-500" />
            {t('login.footer')}
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
