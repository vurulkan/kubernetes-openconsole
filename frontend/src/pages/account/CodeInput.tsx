import React from 'react';
import { useTranslation } from 'react-i18next';
import { Input } from '../../components/ui';

/** A 6-digit code field (the app's code); recovery codes are longer. */
export const CodeInput: React.FC<{
  value: string;
  onChange: (v: string) => void;
  recovery?: boolean;
  label?: string;
  autoFocus?: boolean;
}> = ({ value, onChange, recovery, label, autoFocus }) => {
  const { t } = useTranslation();
  return (
    <Input
      label={label ?? (recovery ? t('twoFactor.recoveryCode') : t('twoFactor.code'))}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      autoComplete="one-time-code"
      inputMode={recovery ? 'text' : 'numeric'}
      maxLength={recovery ? 20 : 6}
      autoFocus={autoFocus}
      spellCheck={false}
      className="w-48 font-mono tracking-widest"
    />
  );
};
