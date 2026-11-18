import React from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Modal } from '../../components/ui';
import { endSession } from '../../services/api';
import { TwoFactorSetupFlow } from './TwoFactorParts';

/**
 * The policy requires two-factor authentication this account hasn't set up:
 * nothing else until it is (Esc, the backdrop and a close button don't close
 * it); the only way out is Sign out.
 */
const TwoFactorEnroll: React.FC<{ onDone: () => void }> = ({ onDone }) => {
  const { t } = useTranslation();
  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950">
      <Modal
        open
        closable={false}
        onClose={() => undefined}
        title={t('twoFactor.enrollTitle')}
        size="md"
        footer={
          <Button variant="outline" size="sm" onClick={endSession}>
            {t('twoFactor.signOut')}
          </Button>
        }
      >
        <p className="mb-4 text-sm text-slate-600 dark:text-slate-300">{t('twoFactor.enrollIntro')}</p>
        <TwoFactorSetupFlow onDone={onDone} />
      </Modal>
    </div>
  );
};

export default TwoFactorEnroll;
