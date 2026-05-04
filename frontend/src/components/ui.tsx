import React, { useEffect, useId, useRef, useState } from 'react';
import { Check, ChevronDown, Search, X } from 'lucide-react';

// ─── Button ─────────────────────────────────────────────────────────────────

type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger';
type ButtonSize = 'sm' | 'md' | 'lg';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const VARIANT_CLS: Record<ButtonVariant, string> = {
  primary: 'bg-blue-600 text-white hover:bg-blue-700 border-transparent',
  secondary: 'bg-slate-100 text-slate-700 hover:bg-slate-200 border-transparent',
  outline: 'bg-white text-slate-700 border-gray-300 hover:bg-gray-50',
  ghost: 'bg-transparent text-slate-600 border-transparent hover:bg-slate-100',
  danger: 'bg-transparent text-red-600 border-transparent hover:bg-red-50',
};

const SIZE_CLS: Record<ButtonSize, string> = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-5 py-2.5 text-sm',
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
    className={`inline-flex items-center justify-center gap-1.5 rounded-lg border font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50 ${VARIANT_CLS[variant]} ${SIZE_CLS[size]} ${className}`}
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
    <div className="flex flex-col gap-1">
      {label && (
        <label htmlFor={inputId} className="text-sm font-medium text-gray-700">
          {label}
        </label>
      )}
      <input
        id={inputId}
        {...props}
        className={`block w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm placeholder:text-gray-400 focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20 disabled:bg-gray-50 disabled:text-gray-500 ${error ? 'border-red-400' : ''} ${className}`}
      />
      {error && <p className="text-xs text-red-500">{error}</p>}
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
  error: 'bg-red-50 border-red-200 text-red-800',
  warning: 'bg-amber-50 border-amber-200 text-amber-800',
  success: 'bg-green-50 border-green-200 text-green-800',
  info: 'bg-blue-50 border-blue-200 text-blue-800',
};

export const Alert: React.FC<AlertProps> = ({ severity, children, className = '' }) => (
  <div className={`rounded-lg border px-4 py-3 text-sm ${ALERT_CLS[severity]} ${className}`}>
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
  default: 'bg-gray-100 text-gray-700',
  success: 'bg-green-100 text-green-700',
  warning: 'bg-amber-100 text-amber-700',
  error: 'bg-red-100 text-red-700',
  info: 'bg-blue-100 text-blue-700',
};

export const Badge: React.FC<BadgeProps> = ({ variant = 'default', children, className = '' }) => (
  <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${BADGE_CLS[variant]} ${className}`}>
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
    className={`inline-block animate-spin rounded-full border-2 border-current border-t-transparent text-blue-600 ${SPINNER_SIZE[size]} ${className}`}
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
}

export const Checkbox: React.FC<CheckboxProps> = ({ checked, onChange, label, disabled, className = '' }) => {
  const id = useId();
  return (
    <label
      htmlFor={id}
      className={`inline-flex cursor-pointer select-none items-center gap-2 ${disabled ? 'cursor-not-allowed opacity-50' : ''} ${className}`}
    >
      <input
        id={id}
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
        className="h-4 w-4 cursor-pointer rounded border-gray-300 accent-blue-600 focus:ring-blue-500"
      />
      {label && <span className="text-sm text-gray-700">{label}</span>}
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
        <div className={`h-5 w-9 rounded-full transition-colors ${checked ? 'bg-blue-600' : 'bg-gray-300'}`} />
        <div
          className={`absolute top-[3px] h-3.5 w-3.5 rounded-full bg-white shadow transition-transform ${checked ? 'translate-x-[19px]' : 'translate-x-[3px]'}`}
        />
      </div>
      {label && <span className="text-sm text-gray-700">{label}</span>}
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
    <div className="flex flex-col gap-1">
      {label && (
        <label htmlFor={selectId} className="text-sm font-medium text-gray-700">
          {label}
        </label>
      )}
      <select
        id={selectId}
        {...props}
        className={`block w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20 ${className}`}
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
    <div className={`flex flex-col gap-1 ${className}`}>
      {label && (
        <label htmlFor={id} className="text-sm font-medium text-gray-700">
          {label}
        </label>
      )}
      <div
        className="relative flex min-h-[38px] cursor-text flex-wrap items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-3 py-2 focus-within:border-blue-500 focus-within:ring-2 focus-within:ring-blue-500/20"
        onClick={() => inputRef.current?.focus()}
      >
        {value.map((chip) => (
          <span
            key={chip}
            className="inline-flex items-center gap-1 rounded bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-800"
          >
            {chip}
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                removeChip(chip);
              }}
              className="text-blue-500 hover:text-blue-800 focus:outline-none"
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
          className="min-w-[120px] flex-1 border-0 bg-transparent text-sm text-gray-900 outline-none placeholder:text-gray-400"
        />
        {showSuggestions && filtered.length > 0 && (
          <div className="absolute left-0 right-0 top-full z-50 mt-1 max-h-48 overflow-auto rounded-lg border border-gray-200 bg-white shadow-lg">
            {filtered.map((s) => (
              <button
                key={s}
                type="button"
                onMouseDown={(e) => {
                  e.preventDefault();
                  addChip(s);
                }}
                className="flex w-full items-center px-3 py-2 text-sm text-gray-700 hover:bg-blue-50 hover:text-blue-700"
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
  const id = useId();

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
        setSearch('');
      }
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
    <div ref={containerRef} className={`relative flex flex-col gap-1 ${className}`}>
      {label && (
        <label htmlFor={id} className="text-sm font-medium text-gray-700">
          {label}
        </label>
      )}
      <button
        id={id}
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex min-h-[38px] w-full flex-wrap items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-3 py-2 text-left text-sm focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
      >
        {value.length === 0 ? (
          <span className="flex-1 text-gray-400">{placeholder}</span>
        ) : (
          value.map((v) => (
            <span
              key={v.id}
              className="inline-flex items-center gap-1 rounded bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-800"
            >
              {v.label}
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onChange(value.filter((item) => item.id !== v.id));
                }}
                className="text-blue-500 hover:text-blue-800"
              >
                <X size={10} />
              </button>
            </span>
          ))
        )}
        <ChevronDown size={14} className="ml-auto shrink-0 text-gray-400" />
      </button>

      {open && (
        <div className="absolute left-0 right-0 top-full z-50 mt-1 rounded-lg border border-gray-200 bg-white shadow-lg">
          <div className="border-b border-gray-100 p-2">
            <div className="relative">
              <Search size={14} className="absolute left-2.5 top-2 text-gray-400" />
              <input
                autoFocus
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search..."
                className="w-full rounded border border-gray-200 py-1.5 pl-7 pr-3 text-sm outline-none focus:border-blue-400"
              />
            </div>
          </div>
          <div className="max-h-48 overflow-auto">
            {filtered.length === 0 ? (
              <p className="px-3 py-2 text-sm text-gray-400">{noOptionsText}</p>
            ) : (
              filtered.map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => toggle(opt)}
                  className="flex w-full items-center gap-2 px-3 py-2 text-sm text-gray-700 hover:bg-blue-50"
                >
                  <div
                    className={`flex h-4 w-4 items-center justify-center rounded border ${
                      isSelected(opt) ? 'border-blue-600 bg-blue-600' : 'border-gray-300'
                    }`}
                  >
                    {isSelected(opt) && <Check size={10} className="text-white" />}
                  </div>
                  {opt.label}
                </button>
              ))
            )}
          </div>
        </div>
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
}

export const Modal: React.FC<ModalProps> = ({ open, onClose, title, children, footer, onKeyDown }) => {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/50" onClick={onClose} />
      <div
        className="relative z-10 flex flex-col rounded-xl bg-white shadow-2xl"
        style={{ width: '95vw', height: '95vh' }}
        onKeyDown={onKeyDown}
        tabIndex={0}
      >
        <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4">
          <h2 className="text-base font-semibold text-gray-900">{title}</h2>
          <button
            onClick={onClose}
            className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600 focus:outline-none"
          >
            <X size={18} />
          </button>
        </div>
        <div className="flex-1 overflow-hidden p-4">{children}</div>
        {footer && (
          <div className="flex justify-end gap-2 border-t border-gray-200 px-6 py-4">{footer}</div>
        )}
      </div>
    </div>
  );
};
