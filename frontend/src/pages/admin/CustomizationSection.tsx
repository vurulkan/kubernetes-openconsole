import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button } from '../../components/ui';
import { deleteLogo, uploadLogo } from '../../services/api';
import { SectionCard } from './SectionCard';

type Status = { status: 'success' | 'error'; message: string } | null;

/** Admin → Customization: the sign-in logo (preview, upload, remove). Makes no request on open. */
export const CustomizationSection: React.FC = () => {
  const { t: tr } = useTranslation();
  const [file, setFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState('/api/customization/logo');
  const [status, setStatus] = useState<Status>(null);

  const upload = async () => {
    if (!file) {
      setStatus({ status: 'error', message: tr('common.logoSelectFile') });
      return;
    }
    setStatus(null);
    try {
      await uploadLogo(file);
      setStatus({ status: 'success', message: tr('common.logoUploaded') });
      setPreviewUrl(`/api/customization/logo?ts=${Date.now()}`);
      setFile(null);
    } catch (err) {
      setStatus({ status: 'error', message: (err as Error).message || tr('admin.customization.uploadFailed') });
    }
  };

  const remove = async () => {
    setStatus(null);
    try {
      await deleteLogo();
      setStatus({ status: 'success', message: tr('common.logoRemoved') });
      setPreviewUrl('');
      setFile(null);
    } catch (err) {
      setStatus({ status: 'error', message: (err as Error).message || tr('admin.customization.removeFailed') });
    }
  };

  return (
    <SectionCard title={tr('admin.cards.loginLogo')}>
      <p className="mb-4 text-sm text-slate-500 dark:text-slate-400">{tr('admin.customization.intro')}</p>

      {previewUrl && (
        <div className="mb-4 w-full max-w-xs overflow-hidden rounded-lg border border-slate-200 dark:border-slate-800 p-2">
          <img
            src={previewUrl}
            alt={tr('admin.customization.logo')}
            onError={() => setPreviewUrl('')}
            className="h-auto w-full max-w-[320px] object-contain"
          />
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <label className="inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 px-4 py-2 text-sm font-medium text-slate-700 dark:text-slate-200 transition-colors hover:bg-slate-50 dark:hover:bg-slate-800/60 dark:bg-slate-900">
          {tr('admin.customization.select')}
          <input type="file" className="hidden" accept="image/*,.svg" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </label>
        <span className="text-sm text-slate-500 dark:text-slate-400">{file ? file.name : tr('common.noFileSelected')}</span>
        <Button variant="primary" size="sm" onClick={upload} disabled={!file}>
          {tr('admin.customization.upload')}
        </Button>
        <Button variant="danger" size="sm" onClick={remove}>
          {tr('admin.customization.remove')}
        </Button>
      </div>

      {status && (
        <Alert severity={status.status} className="mt-3">
          {status.message}
        </Alert>
      )}
    </SectionCard>
  );
};

export default CustomizationSection;
