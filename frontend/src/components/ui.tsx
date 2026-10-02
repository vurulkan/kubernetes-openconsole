import React, { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Check, ChevronDown, Search, X } from 'lucide-react';

// ─── Button ─────────────────────────────────────────────────────────────────

type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger';
type ButtonSize = 'sm' | 'md' | 'lg';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const VARIANT_CLS: Record<ButtonVariant, string> = {
  primary:
    'bg-gradient-to-b from-brand-500 to-brand-600 text-white border-transparent shadow-[0_1px_0_rgba(255,255,255,0.18)_inset,0_1px_2px_rgba(79,70,229,0.35)] hover:from-brand-500 hover:to-brand-700 active:from-brand-600 active:to-brand-700',
  secondary:
    'bg-slate-100 text-slate-800 hover:bg-slate-200 border-transparent dark:bg-slate-800 dark:text-slate-100 dark:hover:bg-slate-700',
  outline:
    'bg-white text-slate-700 border-slate-300 hover:bg-slate-50 hover:border-slate-400 dark:bg-slate-900 dark:text-slate-200 dark:border-slate-700 dark:hover:bg-slate-800/60 dark:hover:border-slate-600',
  ghost:
    'bg-transparent text-slate-600 border-transparent hover:bg-slate-100 hover:text-slate-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-slate-100',
  danger:
    'bg-white text-rose-600 border-rose-200 hover:bg-rose-50 hover:border-rose-300 dark:bg-slate-900 dark:text-rose-300 dark:border-rose-500/30 dark:hover:bg-rose-500/10',
};

const SIZE_CLS: Record<ButtonSize, string> = {
  sm: 'px-3 py-1.5 text-xs h-8',
  md: 'px-4 py-2 text-sm h-9',
  lg: 'px-5 py-2.5 text-sm h-10',
};

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  size = 'md',
  className = '',
  children,
  ...props
}) => (
  <button
    {...props}
    className={`inline-flex cursor-pointer items-center justify-center gap-1.5 whitespace-nowrap rounded-lg border font-medium transition-all duration-150 ease-out focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 focus-visible:ring-offset-2 focus-visible:ring-offset-white disabled:cursor-not-allowed disabled:opacity-50 ${VARIANT_CLS[variant]} ${SIZE_CLS[size]} ${className}`}
  >
    {children}
  </button>
);

// ─── Input ───────────────────────────────────────────────────────────────────

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

export const Input: React.FC<InputProps> = ({ label, error, className = '', id, ...props }) => {
  const autoId = useId();
  const inputId = id ?? autoId;
  return (
    <div className="flex flex-col gap-1.5">
      {label && (
        <label htmlFor={inputId} className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          {label}
        </label>
      )}
      <input
        id={inputId}
        {...props}
        className={`block w-full rounded-lg border px-3 py-2 text-sm shadow-sm transition-colors border-slate-300 bg-white text-slate-900 placeholder:text-slate-400 hover:border-slate-400 focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15 disabled:bg-slate-50 disabled:text-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:placeholder:text-slate-500 dark:hover:border-slate-600 dark:disabled:bg-slate-900/60 dark:disabled:text-slate-500 ${
          error ? 'border-rose-400 focus:border-rose-500 focus:ring-rose-500/15' : ''
        } ${className}`}
      />
      {error && <p className="text-xs text-rose-500">{error}</p>}
    </div>
  );
};

// ─── Alert ───────────────────────────────────────────────────────────────────

type AlertSeverity = 'error' | 'warning' | 'success' | 'info';

interface AlertProps {
  severity: AlertSeverity;
  children: React.ReactNode;
  className?: string;
}

const ALERT_CLS: Record<AlertSeverity, string> = {
  error:
    'bg-rose-50/70 border-rose-200 text-rose-800 ring-rose-500/5 dark:bg-rose-500/10 dark:border-rose-500/30 dark:text-rose-200',
  warning:
    'bg-amber-50/80 border-amber-200 text-amber-900 ring-amber-500/5 dark:bg-amber-500/10 dark:border-amber-500/30 dark:text-amber-200',
  success:
    'bg-emerald-50/80 border-emerald-200 text-emerald-800 ring-emerald-500/5 dark:bg-emerald-500/10 dark:border-emerald-500/30 dark:text-emerald-200',
  info:
    'bg-brand-50/80 border-brand-200 text-brand-800 ring-brand-500/5 dark:bg-brand-500/10 dark:border-brand-500/30 dark:text-brand-200',
};

export const Alert: React.FC<AlertProps> = ({ severity, children, className = '' }) => (
  <div
    className={`rounded-xl border px-4 py-3 text-sm shadow-sm ring-1 ${ALERT_CLS[severity]} ${className}`}
  >
    {children}
  </div>
);

// ─── Badge ───────────────────────────────────────────────────────────────────

type BadgeVariant = 'default' | 'success' | 'warning' | 'error' | 'info';

interface BadgeProps {
  variant?: BadgeVariant;
  children: React.ReactNode;
  className?: string;
}

const BADGE_CLS: Record<BadgeVariant, string> = {
  default:
    'bg-slate-100 text-slate-700 ring-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:ring-slate-700',
  success:
    'bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-500/15 dark:text-emerald-200 dark:ring-emerald-500/30',
  warning:
    'bg-amber-50 text-amber-800 ring-amber-200 dark:bg-amber-500/15 dark:text-amber-200 dark:ring-amber-500/30',
  error:
    'bg-rose-50 text-rose-700 ring-rose-200 dark:bg-rose-500/15 dark:text-rose-200 dark:ring-rose-500/30',
  info:
    'bg-brand-50 text-brand-700 ring-brand-200 dark:bg-brand-500/15 dark:text-brand-200 dark:ring-brand-500/30',
};

export const Badge: React.FC<BadgeProps> = ({ variant = 'default', children, className = '' }) => (
  <span
    className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ring-inset ${BADGE_CLS[variant]} ${className}`}
  >
    {children}
  </span>
);

// ─── Spinner ─────────────────────────────────────────────────────────────────

interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const SPINNER_SIZE: Record<string, string> = { sm: 'h-4 w-4', md: 'h-6 w-6', lg: 'h-8 w-8' };

export const Spinner: React.FC<SpinnerProps> = ({ size = 'md', className = '' }) => (
  <div
    className={`inline-block animate-spin rounded-full border-2 border-current border-t-transparent text-brand-600 dark:text-brand-300 ${SPINNER_SIZE[size]} ${className}`}
    role="status"
    aria-label="Loading"
  />
);

// ─── Checkbox ────────────────────────────────────────────────────────────────

interface CheckboxProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: string;
  disabled?: boolean;
  className?: string;
  /** When true the checkbox renders in the browser's native "mixed" state —
   *  useful for a parent box whose children are partially selected. */
  indeterminate?: boolean;
}

export const Checkbox: React.FC<CheckboxProps> = ({
  checked,
  onChange,
  label,
  disabled,
  className = '',
  indeterminate = false,
}) => {
  const id = useId();
  const ref = React.useRef<HTMLInputElement | null>(null);
  // `indeterminate` isn't a React-controlled attribute, so we poke the DOM
  // after each render — this is the canonical pattern for tri-state checkboxes.
  React.useEffect(() => {
    if (ref.current) ref.current.indeterminate = indeterminate && !checked;
  }, [indeterminate, checked]);
  return (
    <label
      htmlFor={id}
      className={`inline-flex cursor-pointer select-none items-center gap-2 ${disabled ? 'cursor-not-allowed opacity-50' : ''} ${className}`}
    >
      <input
        id={id}
        ref={ref}
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
        className="h-4 w-4 cursor-pointer rounded border-slate-300 dark:border-slate-700 accent-brand-600 focus:ring-brand-500"
      />
      {label && <span className="text-sm text-slate-700 dark:text-slate-200">{label}</span>}
    </label>
  );
};

// ─── Toggle (Switch) ─────────────────────────────────────────────────────────

interface ToggleProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: string;
  className?: string;
}

export const Toggle: React.FC<ToggleProps> = ({ checked, onChange, label, className = '' }) => {
  const id = useId();
  return (
    <label htmlFor={id} className={`inline-flex cursor-pointer select-none items-center gap-2 ${className}`}>
      <div className="relative">
        <input
          id={id}
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          className="sr-only"
        />
        <div
          className={`h-5 w-9 rounded-full transition-colors duration-200 ${
            checked ? 'bg-brand-600' : 'bg-slate-300'
          }`}
        />
        <div
          className={`absolute top-[3px] h-3.5 w-3.5 rounded-full bg-white dark:bg-slate-900 shadow transition-transform duration-200 ${
            checked ? 'translate-x-[19px]' : 'translate-x-[3px]'
          }`}
        />
      </div>
      {label && <span className="text-sm text-slate-700 dark:text-slate-200">{label}</span>}
    </label>
  );
};

// ─── NativeSelect ────────────────────────────────────────────────────────────

interface NativeSelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  children: React.ReactNode;
}

export const NativeSelect: React.FC<NativeSelectProps> = ({ label, className = '', id, children, ...props }) => {
  const autoId = useId();
  const selectId = id ?? autoId;
  return (
    <div className="flex flex-col gap-1.5">
      {label && (
        <label htmlFor={selectId} className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          {label}
        </label>
      )}
      <select
        id={selectId}
        {...props}
        className={`block w-full cursor-pointer rounded-lg border px-3 py-2 text-sm shadow-sm transition-colors border-slate-300 bg-white text-slate-900 hover:border-slate-400 focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:border-slate-600 ${className}`}
      >
        {children}
      </select>
    </div>
  );
};

// ─── ChipInput ───────────────────────────────────────────────────────────────

interface ChipInputProps {
  value: string[];
  onChange: (value: string[]) => void;
  label?: string;
  placeholder?: string;
  suggestions?: string[];
  className?: string;
}

export const ChipInput: React.FC<ChipInputProps> = ({
  value,
  onChange,
  label,
  placeholder,
  suggestions = [],
  className = '',
}) => {
  const [inputValue, setInputValue] = useState('');
  const [showSuggestions, setShowSuggestions] = useState(false);
  const id = useId();
  const inputRef = useRef<HTMLInputElement>(null);

  const addChip = (chip: string) => {
    const trimmed = chip.trim();
    if (trimmed && !value.includes(trimmed)) {
      onChange([...value, trimmed]);
    }
    setInputValue('');
    setShowSuggestions(false);
  };

  const removeChip = (chip: string) => onChange(value.filter((v) => v !== chip));

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addChip(inputValue);
    } else if (e.key === 'Backspace' && !inputValue && value.length > 0) {
      onChange(value.slice(0, -1));
    }
  };

  const filtered = suggestions.filter(
    (s) => s.toLowerCase().includes(inputValue.toLowerCase()) && !value.includes(s)
  );

  return (
    <div className={`flex flex-col gap-1.5 ${className}`}>
      {label && (
        <label htmlFor={id} className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          {label}
        </label>
      )}
      <div
        className="relative flex min-h-[40px] cursor-text flex-wrap items-center gap-1.5 rounded-lg border px-3 py-2 shadow-sm transition-colors border-slate-300 bg-white hover:border-slate-400 focus-within:border-brand-500 focus-within:ring-4 focus-within:ring-brand-500/15 dark:border-slate-700 dark:bg-slate-900 dark:hover:border-slate-600"
        onClick={() => inputRef.current?.focus()}
      >
        {value.map((chip) => (
          <span
            key={chip}
            className="inline-flex items-center gap-1 rounded-md bg-brand-50 dark:bg-brand-500/15 px-2 py-0.5 text-xs font-medium text-brand-700 dark:text-brand-200 ring-1 ring-inset ring-brand-200 dark:ring-brand-500/30"
          >
            {chip}
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                removeChip(chip);
              }}
              className="rounded-sm text-brand-500 transition-colors hover:text-brand-800 focus:outline-none"
            >
              <X size={10} />
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          id={id}
          value={inputValue}
          onChange={(e) => {
            setInputValue(e.target.value);
            setShowSuggestions(true);
          }}
          onKeyDown={handleKeyDown}
          onFocus={() => setShowSuggestions(true)}
          onBlur={() => setTimeout(() => setShowSuggestions(false), 150)}
          placeholder={value.length === 0 ? placeholder : ''}
          className="min-w-[120px] flex-1 border-0 bg-transparent text-sm outline-none text-slate-900 placeholder:text-slate-400 dark:text-slate-100 dark:placeholder:text-slate-500"
        />
        {showSuggestions && filtered.length > 0 && (
          <div className="absolute left-0 right-0 top-full z-50 mt-1 max-h-48 animate-slide-up overflow-auto rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-elevated">
            {filtered.map((s) => (
              <button
                key={s}
                type="button"
                onMouseDown={(e) => {
                  e.preventDefault();
                  addChip(s);
                }}
                className="flex w-full items-center px-3 py-2 text-sm text-slate-700 dark:text-slate-200 transition-colors hover:bg-brand-50 dark:bg-brand-500/15 hover:text-brand-700 dark:text-brand-200"
              >
                {s}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// ─── MultiSelect ─────────────────────────────────────────────────────────────

export interface MultiSelectOption {
  id: number | string;
  label: string;
}

interface MultiSelectProps {
  options: MultiSelectOption[];
  value: MultiSelectOption[];
  onChange: (value: MultiSelectOption[]) => void;
  placeholder?: string;
  noOptionsText?: string;
  className?: string;
  label?: string;
}

export const MultiSelect: React.FC<MultiSelectProps> = ({
  options,
  value,
  onChange,
  placeholder = 'Select...',
  noOptionsText = 'No options',
  className = '',
  label,
}) => {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [menuPos, setMenuPos] = useState<{ top: number; left: number; width: number } | null>(null);
  const id = useId();

  // Portal the dropdown to document.body so it escapes any ancestor with
  // overflow:hidden (table rows, cards, drawers). Measure the trigger button
  // in viewport coords on every open/resize/scroll.
  useLayoutEffect(() => {
    if (!open || !buttonRef.current) return;
    const update = () => {
      const rect = buttonRef.current!.getBoundingClientRect();
      setMenuPos({ top: rect.bottom + 4, left: rect.left, width: rect.width });
    };
    update();
    window.addEventListener('resize', update);
    window.addEventListener('scroll', update, true);
    return () => {
      window.removeEventListener('resize', update);
      window.removeEventListener('scroll', update, true);
    };
  }, [open]);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      const target = e.target as Node;
      if (containerRef.current?.contains(target)) return;
      if (menuRef.current?.contains(target)) return;
      setOpen(false);
      setSearch('');
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const filtered = options.filter((opt) =>
    opt.label.toLowerCase().includes(search.toLowerCase())
  );

  const isSelected = (opt: MultiSelectOption) => value.some((v) => v.id === opt.id);

  const toggle = (opt: MultiSelectOption) => {
    if (isSelected(opt)) {
      onChange(value.filter((v) => v.id !== opt.id));
    } else {
      onChange([...value, opt]);
    }
  };

  return (
    <div ref={containerRef} className={`relative flex flex-col gap-1.5 ${className}`}>
      {label && (
        <label htmlFor={id} className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
          {label}
        </label>
      )}
      <button
        ref={buttonRef}
        id={id}
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex min-h-[40px] w-full cursor-pointer flex-wrap items-center gap-1.5 rounded-lg border px-3 py-2 text-left text-sm shadow-sm transition-colors border-slate-300 bg-white text-slate-900 hover:border-slate-400 focus:border-brand-500 focus:outline-none focus:ring-4 focus:ring-brand-500/15 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:border-slate-600"
      >
        {value.length === 0 ? (
          <span className="flex-1 text-slate-400 dark:text-slate-500">{placeholder}</span>
        ) : (
          value.map((v) => (
            <span
              key={v.id}
              className="inline-flex items-center gap-1 rounded-md bg-brand-50 dark:bg-brand-500/15 px-2 py-0.5 text-xs font-medium text-brand-700 dark:text-brand-200 ring-1 ring-inset ring-brand-200 dark:ring-brand-500/30"
            >
              {v.label}
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onChange(value.filter((item) => item.id !== v.id));
                }}
                className="rounded-sm text-brand-500 hover:text-brand-800"
              >
                <X size={10} />
              </button>
            </span>
          ))
        )}
        <ChevronDown size={14} className="ml-auto shrink-0 text-slate-400 dark:text-slate-500" />
      </button>

      {open && menuPos && createPortal(
        <div
          ref={menuRef}
          className="fixed z-[1000] animate-slide-up rounded-xl border border-slate-200 bg-white shadow-elevated dark:border-slate-800 dark:bg-slate-900"
          style={{ top: menuPos.top, left: menuPos.left, width: menuPos.width }}
        >
          <div className="border-b border-slate-100 p-2 dark:border-slate-800">
            <div className="relative">
              <Search size={14} className="absolute left-2.5 top-2 text-slate-400 dark:text-slate-500" />
              <input
                autoFocus
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search..."
                className="w-full rounded-md border py-1.5 pl-7 pr-3 text-sm outline-none border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:border-brand-400 focus:ring-2 focus:ring-brand-500/15 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:placeholder:text-slate-500"
              />
            </div>
          </div>
          <div className="max-h-48 overflow-auto">
            {filtered.length === 0 ? (
              <p className="px-3 py-2 text-sm text-slate-400 dark:text-slate-500">{noOptionsText}</p>
            ) : (
              filtered.map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => toggle(opt)}
                  className="flex w-full cursor-pointer items-center gap-2 px-3 py-2 text-sm text-slate-700 transition-colors hover:bg-brand-50 dark:text-slate-200 dark:hover:bg-brand-500/15"
                >
                  <div
                    className={`flex h-4 w-4 items-center justify-center rounded border transition-colors ${
                      isSelected(opt)
                        ? 'border-brand-600 bg-brand-600'
                        : 'border-slate-300 dark:border-slate-700'
                    }`}
                  >
                    {isSelected(opt) && <Check size={10} className="text-white" />}
                  </div>
                  {opt.label}
                </button>
              ))
            )}
          </div>
        </div>,
        document.body
      )}
    </div>
  );
};

// ─── Modal ───────────────────────────────────────────────────────────────────

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  onKeyDown?: React.KeyboardEventHandler<HTMLDivElement>;
  /** 'full' = 95vw × 95vh for data-dense content; 'lg' = 64rem for wide forms;
   *  'md' / 'sm' for confirmations. */
  size?: 'full' | 'lg' | 'md' | 'sm';
}

export const Modal: React.FC<ModalProps> = ({
  open,
  onClose,
  title,
  children,
  footer,
  onKeyDown,
  size = 'full',
}) => {
  useEffect(() => {
    if (!open) return;
    // Register as the active modal scope so page shortcuts suspend.
    // Lazy import avoids a circular dep with the hook file.
    let push: (() => void) | undefined;
    let pop: (() => void) | undefined;
    import('../hooks/useScopedShortcuts').then((m) => {
      push = m.pushModalScope;
      pop = m.popModalScope;
      push();
    });
    // Lock body scroll so wheeling over the backdrop doesn't move content
    // behind the modal — that scroll makes the dialog appear to float away
    // from where it was opened, which operators report as "opens too far
    // down". Save the previous value so a nested modal unwinds cleanly.
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    };
    document.addEventListener('keydown', handler);
    return () => {
      document.removeEventListener('keydown', handler);
      document.body.style.overflow = prevOverflow;
      if (pop) pop();
    };
  }, [open, onClose]);

  if (!open) return null;

  // Non-full modals clamp to the viewport so long content (shortcuts list,
  // long error, long YAML preview) scrolls inside the body instead of
  // pushing header/footer off-screen. The outer wrapper already provides
  // 1rem padding; we leave 2rem total headroom.
  const dialogStyle: React.CSSProperties =
    size === 'sm'
      ? { width: 'min(26rem, 95vw)', maxHeight: 'calc(100vh - 2rem)' }
      : size === 'md'
      ? { width: 'min(40rem, 95vw)', maxHeight: 'calc(100vh - 2rem)' }
      : size === 'lg'
      ? { width: 'min(64rem, 95vw)', maxHeight: 'calc(100vh - 2rem)' }
      : { width: '95vw', height: '95vh' };
  const bodyClass =
    size === 'full'
      ? 'flex-1 overflow-hidden p-4'
      // sm/md/lg all scroll inside the body when content overflows so the
      // header and footer stay pinned.
      : 'flex-1 min-h-0 overflow-auto p-5';

  return (
    <div className="fixed inset-0 z-50 flex animate-fade-in items-center justify-center p-4">
      <div className="absolute inset-0 bg-slate-900/50 backdrop-blur-sm" onClick={onClose} />
      <div
        className="relative z-10 flex animate-slide-up flex-col overflow-hidden rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-elevated"
        style={dialogStyle}
        onKeyDown={onKeyDown}
        tabIndex={0}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 px-5 py-3">
          <h2 className="text-sm font-semibold tracking-tight text-slate-900 dark:text-slate-100">
            {title}
          </h2>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition-colors hover:bg-slate-100 hover:text-slate-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500/60 dark:hover:bg-slate-800 dark:hover:text-slate-100"
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>
        <div className={bodyClass}>{children}</div>
        {footer && (
          <div className="flex justify-end gap-2 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 px-5 py-3">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
};
