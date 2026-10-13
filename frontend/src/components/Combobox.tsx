import React, { useEffect, useId, useMemo, useRef, useState } from 'react';
import { X } from 'lucide-react';
import { useTranslation } from 'react-i18next';

/** How the chosen value should match: typed text, a picked option, or a whole family ("pod.exec.*"). */
export type ComboMode = 'contains' | 'exact' | 'family';

type Props = {
  label: string;
  value: string;
  onChange: (value: string, mode: ComboMode) => void;
  options: string[];
  /** Group dotted values ("pod.exec.start") under a selectable family row ("pod.exec.*"). */
  families?: boolean;
  placeholder?: string;
  className?: string;
};

type Row = { value: string; mode: ComboMode; label: string; indent: boolean };

const MAX_ROWS = 60;

/**
 * Text input with a filtered suggestion list (WAI-ARIA combobox). Typing
 * filters by "contains"; picking a row matches it exactly, or a whole family.
 */
const Combobox: React.FC<Props> = ({ label, value, onChange, options, families, placeholder, className = '' }) => {
  const { t } = useTranslation();
  const id = useId();
  const listId = `${id}-list`;
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const rootRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);

  const rows = useMemo<Row[]>(() => {
    const q = value.trim().toLowerCase();
    const hit = (s: string) => !q || s.toLowerCase().includes(q);
    if (!families) {
      return options.filter(hit).slice(0, MAX_ROWS).map((o) => ({ value: o, mode: 'exact', label: o, indent: false }));
    }
    const groups = new Map<string, string[]>();
    for (const o of options) {
      const cut = o.lastIndexOf('.');
      const family = cut > 0 ? o.slice(0, cut) : o;
      groups.set(family, [...(groups.get(family) ?? []), o]);
    }
    const out: Row[] = [];
    for (const [family, members] of groups) {
      const shown = members.filter(hit);
      const familyHit = hit(`${family}.*`);
      if (!familyHit && shown.length === 0) continue;
      if (members.length > 1) {
        out.push({ value: `${family}.*`, mode: 'family', label: `${family}.*`, indent: false });
      }
      for (const m of familyHit && shown.length === 0 ? members : shown) {
        out.push({ value: m, mode: 'exact', label: m, indent: members.length > 1 });
      }
      if (out.length >= MAX_ROWS) break;
    }
    return out.slice(0, MAX_ROWS);
  }, [options, value, families]);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [open]);

  useEffect(() => {
    if (active < 0) return;
    listRef.current?.querySelector(`[data-index="${active}"]`)?.scrollIntoView?.({ block: 'nearest' });
  }, [active]);

  const pick = (row: Row) => {
    onChange(row.value, row.mode);
    setOpen(false);
    setActive(-1);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (!open) setOpen(true);
      if (rows.length === 0) return;
      const step = e.key === 'ArrowDown' ? 1 : -1;
      setActive((i) => (i < 0 && step < 0 ? rows.length - 1 : (i + step + rows.length) % rows.length));
    } else if (e.key === 'Enter') {
      if (open && active >= 0 && rows[active]) {
        e.preventDefault();
        pick(rows[active]);
      } else {
        setOpen(false);
      }
    } else if (e.key === 'Escape') {
      if (open) {
        e.preventDefault();
        e.stopPropagation();
        setOpen(false);
        setActive(-1);
      }
    } else if (e.key === 'Tab') {
      setOpen(false);
    }
  };

  const showList = open && rows.length > 0;

  return (
    <div ref={rootRef} className={`relative flex flex-col gap-1.5 ${className}`}>
      <label htmlFor={id} className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
        {label}
      </label>
      <div className="relative">
        <input
          id={id}
          role="combobox"
          aria-autocomplete="list"
          aria-expanded={showList}
          aria-controls={listId}
          aria-activedescendant={showList && active >= 0 ? `${id}-opt-${active}` : undefined}
          autoComplete="off"
          spellCheck={false}
          value={value}
          placeholder={placeholder}
          onChange={(e) => {
            onChange(e.target.value, 'contains');
            setOpen(true);
            setActive(-1);
          }}
          onFocus={() => setOpen(true)}
          onClick={() => setOpen(true)}
          onKeyDown={onKeyDown}
          className="block w-full rounded-lg border border-slate-300 bg-white py-2 pl-3 pr-8 text-sm text-slate-900 shadow-sm transition-colors placeholder:text-slate-400 hover:border-slate-400 focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:border-slate-600"
        />
        {value && (
          <button
            type="button"
            aria-label={t('combobox.clear', { label })}
            onClick={() => {
              onChange('', 'contains');
              setActive(-1);
            }}
            className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-1 text-slate-500 hover:bg-slate-100 hover:text-slate-700 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200"
          >
            <X size={13} />
          </button>
        )}
      </div>
      <ul
        ref={listRef}
        id={listId}
        role="listbox"
        aria-label={label}
        hidden={!showList}
        className="absolute left-0 top-full z-30 mt-1 max-h-72 min-w-full overflow-auto rounded-xl border border-slate-200 bg-white py-1 shadow-elevated dark:border-slate-800 dark:bg-slate-900"
      >
        {rows.map((row, i) => (
          <li
            key={`${row.mode}:${row.value}`}
            id={`${id}-opt-${i}`}
            data-index={i}
            role="option"
            aria-selected={i === active}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => pick(row)}
            onMouseEnter={() => setActive(i)}
            className={`cursor-pointer whitespace-nowrap px-3 py-1.5 font-mono text-xs ${row.indent ? 'pl-7' : ''} ${
              row.mode === 'family' ? 'font-semibold text-slate-900 dark:text-slate-100' : 'text-slate-700 dark:text-slate-300'
            } ${i === active ? 'bg-brand-50 dark:bg-brand-500/15' : ''}`}
          >
            {row.label}
            {row.mode === 'family' && (
              <span className="ml-2 font-sans text-[11px] font-normal text-slate-500 dark:text-slate-400">
                {t('combobox.allInFamily')}
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
};

export default Combobox;
