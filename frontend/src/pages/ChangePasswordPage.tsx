import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
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
    <div className="flex min-h-screen items-center justify-center bg-slate-50 p-4 font-sans">
      <div className="w-full max-w-sm rounded-xl border border-gray-200 bg-white p-8 shadow-sm">
        <h1 className="mb-1 text-xl font-semibold text-gray-900">Update Your Password</h1>
        <p className="mb-6 text-sm text-gray-500">Your first login requires a password update.</p>

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
            {loading ? 'Updating...' : 'Update Password'}
          </Button>
        </form>
      </div>
    </div>
  );
};

export default ChangePasswordPage;
