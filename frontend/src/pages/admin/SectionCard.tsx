import React from 'react';

/** A titled card inside an Admin tab. */
export const SectionCard: React.FC<{ title: string; description?: string; children: React.ReactNode }> = ({
  title,
  description,
  children,
}) => (
  <section className="card-surface p-5">
    <header className="mb-4 flex items-start justify-between gap-3">
      <div>
        <h2 className="text-sm font-semibold tracking-tight text-slate-900 dark:text-slate-100">{title}</h2>
        {description && <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{description}</p>}
      </div>
    </header>
    {children}
  </section>
);

export default SectionCard;
