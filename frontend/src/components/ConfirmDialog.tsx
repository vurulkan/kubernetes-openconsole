import React, { useEffect, useState } from 'react';
import { Button, Modal } from './ui';

export type ConfirmOptions = {
  title: string;
  message: React.ReactNode;
  confirmText?: string;
  cancelText?: string;
  variant?: 'default' | 'danger';
};

type Pending = ConfirmOptions & { resolve: (ok: boolean) => void };

// Imperative confirm() backed by a single in-app modal. Call sites don't need
// to render anything or thread props; they just await confirm({...}).
let openFn: ((opts: ConfirmOptions) => Promise<boolean>) | null = null;

export const confirm = (opts: ConfirmOptions): Promise<boolean> => {
  if (openFn) return openFn(opts);
  // Fallback to native when the provider is not mounted yet (startup races).
  return Promise.resolve(window.confirm(typeof opts.message === 'string' ? opts.message : opts.title));
};

/**
 * Mount once near the top of the tree (App.tsx). Hosts a single Modal and
 * exposes the imperative confirm() helper via a module-level register.
 */
export const ConfirmProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [pending, setPending] = useState<Pending | null>(null);

  useEffect(() => {
    openFn = (opts) =>
      new Promise<boolean>((resolve) => {
        setPending({ ...opts, resolve });
      });
    return () => {
      openFn = null;
    };
  }, []);

  const close = (ok: boolean) => {
    if (pending) {
      pending.resolve(ok);
      setPending(null);
    }
  };

  return (
    <>
      {children}
      {pending && (
        <Modal
          open
          onClose={() => close(false)}
          title={pending.title}
          size="sm"
          footer={
            <>
              <Button variant="outline" size="sm" onClick={() => close(false)}>
                {pending.cancelText ?? 'Cancel'}
              </Button>
              <Button
                variant={pending.variant === 'danger' ? 'danger' : 'primary'}
                size="sm"
                onClick={() => close(true)}
              >
                {pending.confirmText ?? 'Confirm'}
              </Button>
            </>
          }
        >
          <div className="text-sm text-slate-700 dark:text-slate-200">{pending.message}</div>
        </Modal>
      )}
    </>
  );
};

export default ConfirmProvider;
