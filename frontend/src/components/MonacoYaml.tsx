import React, { Suspense, lazy } from 'react';

// Monaco is the heaviest frontend dependency we have; lazy-loading it keeps
// Dashboard first-paint untouched for the (common) read-only path. The chunk
// only comes down the wire when the user actually opens the YAML modal.
const Editor = lazy(() => import('@monaco-editor/react').then((m) => ({ default: m.Editor })));
const DiffEditor = lazy(() => import('@monaco-editor/react').then((m) => ({ default: m.DiffEditor })));

type YamlEditorProps = {
  value: string;
  onChange?: (next: string) => void;
  readOnly?: boolean;
  height?: string | number;
  theme?: 'vs' | 'vs-dark';
};

const commonEditorOptions = {
  minimap: { enabled: false },
  scrollBeyondLastLine: false,
  automaticLayout: true,
  tabSize: 2,
  wordWrap: 'on' as const,
  renderWhitespace: 'boundary' as const,
  // Keep context menu light — the editor isn't a general-purpose IDE.
  contextmenu: false,
};

const Fallback = (
  <div className="flex h-full items-center justify-center text-xs text-slate-500 dark:text-slate-400">
    Loading editor…
  </div>
);

export const YamlEditor: React.FC<YamlEditorProps> = ({
  value,
  onChange,
  readOnly,
  height = '100%',
  theme = 'vs',
}) => (
  <Suspense fallback={Fallback}>
    <Editor
      language="yaml"
      value={value}
      onChange={(v) => onChange?.(v ?? '')}
      height={height}
      theme={theme}
      options={{ ...commonEditorOptions, readOnly: !!readOnly }}
    />
  </Suspense>
);

type DiffProps = {
  original: string;
  modified: string;
  onModifiedChange?: (next: string) => void;
  height?: string | number;
  theme?: 'vs' | 'vs-dark';
};

/**
 * Side-by-side YAML diff with the right-hand pane editable. "original" is the
 * read-only server copy; "modified" is the operator's draft that goes to apply.
 */
export const YamlDiff: React.FC<DiffProps> = ({
  original,
  modified,
  onModifiedChange,
  height = '100%',
  theme = 'vs',
}) => (
  <Suspense fallback={Fallback}>
    <DiffEditor
      language="yaml"
      original={original}
      modified={modified}
      height={height}
      theme={theme}
      options={{
        ...commonEditorOptions,
        renderSideBySide: true,
        originalEditable: false,
        readOnly: !onModifiedChange,
      }}
      onMount={(editor) => {
        if (!onModifiedChange) return;
        const modifiedEditor = editor.getModifiedEditor();
        modifiedEditor.onDidChangeModelContent(() => {
          onModifiedChange(modifiedEditor.getValue());
        });
      }}
    />
  </Suspense>
);
