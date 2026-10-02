import React from 'react';
import { useTranslation } from 'react-i18next';
import { Languages } from 'lucide-react';
import { persistLocale, SUPPORTED_LOCALES, SupportedLocale } from '../i18n';

const LOCALE_LABELS: Record<SupportedLocale, string> = {
  en: 'EN',
  tr: 'TR',
};

/**
 * Compact locale toggle shown next to the theme toggle. Keeps the surface
 * tiny — a two-letter chip per locale, no menu — because we only ship two
 * languages today. If a third one lands this becomes a dropdown.
 */
const LocaleSwitcher: React.FC<{ className?: string }> = ({ className = '' }) => {
  const { i18n } = useTranslation();
  const current = (i18n.language.slice(0, 2) as SupportedLocale);
  return (
    <div
      className={`inline-flex items-center gap-0.5 rounded-md border border-slate-200 bg-white/60 p-0.5 dark:border-slate-700 dark:bg-slate-900/60 ${className}`}
      role="group"
      aria-label="Language"
    >
      <Languages size={12} className="ml-1 text-slate-400 dark:text-slate-500" />
      {SUPPORTED_LOCALES.map((l) => {
        const active = current === l;
        return (
          <button
            key={l}
            type="button"
            onClick={() => {
              if (active) return;
              void i18n.changeLanguage(l);
              persistLocale(l);
            }}
            aria-pressed={active}
            aria-label={LOCALE_LABELS[l]}
            className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase transition-colors ${
              active
                ? 'bg-brand-50 text-brand-700 dark:bg-brand-500/15 dark:text-brand-200'
                : 'text-slate-500 hover:bg-slate-100 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100'
            }`}
          >
            {LOCALE_LABELS[l]}
          </button>
        );
      })}
    </div>
  );
};

export default LocaleSwitcher;
