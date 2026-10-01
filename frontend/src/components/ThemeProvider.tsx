import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { Monitor, Moon, Sun } from 'lucide-react';

type ThemeMode = 'light' | 'dark' | 'system';
type ThemeEffective = 'light' | 'dark';

type ThemeCtx = {
  mode: ThemeMode;
  effective: ThemeEffective;
  setMode: (mode: ThemeMode) => void;
};

const STORAGE_KEY = 'theme-mode';
const Context = createContext<ThemeCtx | null>(null);

const resolveEffective = (mode: ThemeMode): ThemeEffective => {
  if (mode === 'system') {
    try {
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    } catch (err) {
      return 'light';
    }
  }
  return mode;
};

const applyEffective = (effective: ThemeEffective) => {
  const root = document.documentElement;
  if (effective === 'dark') {
    root.classList.add('dark');
  } else {
    root.classList.remove('dark');
  }
};

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [mode, setModeState] = useState<ThemeMode>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored === 'light' || stored === 'dark' || stored === 'system') {
        return stored;
      }
    } catch (err) {
      /* ignore */
    }
    return 'system';
  });
  const [effective, setEffective] = useState<ThemeEffective>(() => resolveEffective('system'));

  useEffect(() => {
    const next = resolveEffective(mode);
    setEffective(next);
    applyEffective(next);
  }, [mode]);

  useEffect(() => {
    if (mode !== 'system') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const listener = () => {
      const next = resolveEffective('system');
      setEffective(next);
      applyEffective(next);
    };
    mq.addEventListener('change', listener);
    return () => mq.removeEventListener('change', listener);
  }, [mode]);

  const setMode = (next: ThemeMode) => {
    setModeState(next);
    try {
      localStorage.setItem(STORAGE_KEY, next);
    } catch (err) {
      /* ignore */
    }
  };

  const value = useMemo<ThemeCtx>(() => ({ mode, effective, setMode }), [mode, effective]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
};

export const useTheme = (): ThemeCtx => {
  const ctx = useContext(Context);
  if (!ctx) {
    throw new Error('useTheme must be used within <ThemeProvider>');
  }
  return ctx;
};

const OPTIONS: Array<{ value: ThemeMode; label: string; Icon: React.ComponentType<{ size?: number }> }> = [
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
  { value: 'system', label: 'System', Icon: Monitor },
];

export const ThemeToggle: React.FC<{ className?: string }> = ({ className = '' }) => {
  const { mode, setMode } = useTheme();
  return (
    <div
      className={`inline-flex items-center gap-0.5 rounded-lg border border-slate-200 bg-white/80 p-0.5 backdrop-blur-sm dark:border-slate-800 dark:bg-slate-900/70 ${className}`}
      role="group"
      aria-label="Theme"
    >
      {OPTIONS.map(({ value, label, Icon }) => {
        const active = mode === value;
        return (
          <button
            key={value}
            type="button"
            onClick={() => setMode(value)}
            aria-pressed={active}
            title={label}
            className={`flex h-7 w-7 items-center justify-center rounded-md transition-colors ${
              active
                ? 'bg-brand-50 text-brand-700 ring-1 ring-inset ring-brand-200 dark:bg-brand-500/15 dark:text-brand-200 dark:ring-brand-500/30'
                : 'text-slate-500 hover:bg-slate-100 hover:text-slate-700 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100'
            }`}
          >
            <Icon size={14} />
          </button>
        );
      })}
    </div>
  );
};
