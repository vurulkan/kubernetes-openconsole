import React, { useRef, useState } from 'react';
import { DayPicker } from 'react-day-picker';
import { enUS, tr as trLocale } from 'react-day-picker/locale';
import { CalendarDays } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Input } from './ui';

const ISO = /^(\d{4})-(\d{2})-(\d{2})$/;

/** YYYY-MM-DD → a local date, or undefined when it isn't a real day. */
export const parseDay = (v: string): Date | undefined => {
  const m = ISO.exec(v);
  if (!m) return undefined;
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
  return d.getMonth() === Number(m[2]) - 1 ? d : undefined;
};

export const isoDay = (d: Date) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;

/** Why v (YYYY-MM-DD) isn't accepted, '' when it is (empty is accepted: the field is optional or a choice elsewhere says so). */
export const dayError = (v: string, min: string | undefined, max: string | undefined, t: TFunction) => {
  if (!v) return '';
  if (!parseDay(v)) return t('dateField.invalid');
  if (max && v > max) return t('dateField.afterMax', { date: max });
  if (min && v < min) return t('dateField.beforeMin', { date: min });
  return '';
};

// Fingers: the phone's own date picker (full screen on iOS / Android) is easier than a small grid.
const coarsePointer = () => typeof window !== 'undefined' && !!window.matchMedia?.('(pointer: coarse)').matches;

const dayClass =
  'h-9 w-9 p-0 text-center text-sm [&>button]:h-9 [&>button]:w-9 [&>button]:rounded-md [&>button]:focus:outline-none [&>button]:focus-visible:ring-2 [&>button]:focus-visible:ring-brand-500/60';

/**
 * A date (YYYY-MM-DD, local). With a mouse / keyboard: a text field plus a calendar
 * (react-day-picker, unstyled + Tailwind) where days outside min / max are faded, struck
 * through and can't be picked; on a touch screen the browser's date field with min / max.
 * Both show the same inline error for a typed day outside the range. onChange gets a whole
 * day (YYYY-MM-DD) or '' while the text isn't one, never a half-typed value. One box like
 * every other field (the calendar button sits inside it); className sizes the whole field,
 * size="sm" (h-8) sits in a row of small buttons.
 */
export const DateField: React.FC<{
  value: string;
  onChange: (v: string) => void;
  label?: string;
  'aria-label'?: string;
  min?: string;
  max?: string;
  className?: string;
  size?: 'sm';
}> = ({ value, onChange, label, min, max, className = '', size, ...rest }) => {
  const { t, i18n } = useTranslation();
  const [coarse] = useState(coarsePointer);
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const [text, setText] = useState(value);
  // A change from outside (a filter cleared) replaces the text; what this field sent doesn't.
  const [sent, setSent] = useState(value);
  if (value !== sent) {
    setSent(value);
    setText(value);
  }
  const type = (v: string) => {
    const out = v === '' || parseDay(v) ? v : '';
    setText(v);
    setSent(out);
    onChange(out);
  };
  const error = dayError(text, min, max, t);
  const name = label ?? rest['aria-label'] ?? '';
  const box = size === 'sm' ? 'h-8' : '';

  if (coarse) {
    return (
      <Input
        type="date"
        label={label}
        aria-label={rest['aria-label']}
        value={text}
        min={min}
        max={max}
        error={error || undefined}
        onChange={(e) => type(e.target.value)}
        className={box}
      />
    );
  }

  const close = (refocus: boolean) => {
    setOpen(false);
    if (refocus) buttonRef.current?.focus();
  };
  const selected = parseDay(text);
  const fromDay = min ? parseDay(min) : undefined;
  const toDay = max ? parseDay(max) : undefined;
  const disabled = [...(fromDay ? [{ before: fromDay }] : []), ...(toDay ? [{ after: toDay }] : [])];

  return (
    <div
      ref={wrapRef}
      className={`relative ${className}`}
      onBlur={(e) => {
        if (open && !wrapRef.current?.contains(e.relatedTarget as Node | null)) setOpen(false);
      }}
    >
      <div className="relative">
        <Input
          label={label}
          aria-label={rest['aria-label']}
          value={text}
          placeholder={t('dateField.placeholder')}
          inputMode="numeric"
          maxLength={10}
          error={error || undefined}
          onChange={(e) => type(e.target.value.trim())}
          className={`pr-9 tabular-nums ${box}`}
        />
        <button
          ref={buttonRef}
          type="button"
          aria-haspopup="dialog"
          aria-expanded={open}
          aria-label={t('dateField.open', { name })}
          title={t('dateField.open', { name })}
          onClick={() => setOpen((v) => !v)}
          // Inside the box, on its right: bottom-aligned so a label above or an error below doesn't move it.
          className={`absolute right-1 ${error ? 'bottom-[26px]' : 'bottom-1'} flex ${size === 'sm' ? 'h-6 w-6' : 'h-7 w-7'} items-center justify-center rounded-md text-slate-500 hover:bg-slate-100 hover:text-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200`}
        >
          <CalendarDays size={15} aria-hidden="true" />
        </button>
      </div>
      {open && (
        <div
          role="dialog"
          aria-label={t('dateField.calendar', { name })}
          className="absolute left-0 top-full z-50 mt-1 rounded-xl border border-slate-200 bg-white p-3 shadow-elevated dark:border-slate-700 dark:bg-slate-900"
          onKeyDown={(e) => {
            if (e.key !== 'Escape') return;
            e.preventDefault();
            e.stopPropagation(); // a surrounding dialog stays open
            close(true);
          }}
        >
          <DayPicker
            mode="single"
            autoFocus
            fixedWeeks
            showOutsideDays
            locale={i18n.language?.startsWith('tr') ? trLocale : enUS}
            weekStartsOn={1}
            selected={selected}
            defaultMonth={selected ?? (toDay && toDay < new Date() ? toDay : undefined)}
            disabled={disabled}
            onSelect={(d) => {
              if (!d) return;
              type(isoDay(d));
              close(true);
            }}
            classNames={{
              root: 'text-slate-800 dark:text-slate-100',
              months: 'relative',
              month_caption: 'flex h-9 items-center justify-center text-sm font-semibold',
              nav: 'absolute inset-x-0 top-0 flex h-9 items-center justify-between',
              button_previous:
                'flex h-8 w-8 items-center justify-center rounded-md text-slate-500 hover:bg-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 disabled:opacity-30 dark:text-slate-400 dark:hover:bg-slate-800',
              button_next:
                'flex h-8 w-8 items-center justify-center rounded-md text-slate-500 hover:bg-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 disabled:opacity-30 dark:text-slate-400 dark:hover:bg-slate-800',
              chevron: 'h-4 w-4 fill-current',
              month_grid: 'mt-1 border-collapse',
              weekdays: '',
              weekday: 'h-8 w-9 text-center text-[11px] font-medium uppercase text-slate-500 dark:text-slate-400',
              week: '',
              day: dayClass,
              day_button: 'hover:bg-slate-100 dark:hover:bg-slate-800',
              outside: 'text-slate-500 dark:text-slate-400',
              today: 'font-bold text-brand-700 dark:text-brand-300',
              selected: '[&>button]:bg-brand-600 [&>button]:text-white [&>button]:hover:bg-brand-600 dark:[&>button]:bg-brand-500',
              disabled:
                'text-slate-400 dark:text-slate-600 [&>button]:cursor-not-allowed [&>button]:line-through [&>button]:decoration-slate-400 [&>button]:hover:bg-transparent dark:[&>button]:decoration-slate-500',
            }}
          />
        </div>
      )}
    </div>
  );
};
