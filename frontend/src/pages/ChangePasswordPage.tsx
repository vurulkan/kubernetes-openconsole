import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { KeyRound } from 'lucide-react';
import { Alert, Button, Input } from '../components/ui';
import { changePassword } from '../services/api';

type Props = {
  onChanged: () => Promise<void>;
};

const ChangePasswordPage: React.FC<Props> = ({ onChanged }) => {
  const navigate = useNavigate();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setSuccess(false);
    try {
      await changePassword(currentPassword, newPassword);
      setSuccess(true);
      setCurrentPassword('');
      setNewPassword('');
      await onChanged();
      navigate('/');
    } catch (err) {
      setError('Password change failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center p-4 font-sans">
      <div className="pointer-events-none absolute inset-0 bg-brand-radial" aria-hidden="true" />
      <div className="relative w-full max-w-md rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-slate-900/85 p-8 shadow-elevated backdrop-blur-sm">
        <div className="mb-5 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-50 dark:bg-brand-500/15 ring-1 ring-inset ring-brand-200 dark:ring-brand-500/30">
            <KeyRound size={18} className="text-brand-600 dark:text-brand-300" />
          </div>
          <div className="leading-tight">
            <h1 className="text-base font-semibold tracking-tight text-slate-900 dark:text-slate-100">
              Update your password
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">A password update is required for first login.</p>
          </div>
        </div>

        {error && (
          <Alert severity="error" className="mb-4">
            {error}
          </Alert>
        )}
        {success && (
          <Alert severity="success" className="mb-4">
            Password updated.
          </Alert>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <Input
            label="Current Password"
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            autoComplete="current-password"
          />
          <Input
            label="New Password"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            autoComplete="new-password"
          />
          <Button type="submit" variant="primary" disabled={loading} className="w-full">
            {loading ? 'Updating…' : 'Update Password'}
          </Button>
        </form>
      </div>
    </div>
  );
};

export default ChangePasswordPage;
