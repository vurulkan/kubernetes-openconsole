// Monaco served from our own bundle (not jsDelivr): the YAML editor works in
// an air-gapped cluster and the CSP stays 'self'. Only the editor core, the
// YAML tokenizer and the base worker are bundled; this module is loaded
// lazily (MonacoYaml.tsx), so it costs nothing until a YAML dialog opens.
import * as monaco from 'monaco-editor/editor';
import 'monaco-editor/features/register.all';
import 'monaco-editor/languages/definitions/yaml/register';
import EditorWorker from 'monaco-editor/editor/editor.worker?worker';
import { loader } from '@monaco-editor/react';

self.MonacoEnvironment = { getWorker: () => new EditorWorker() };
loader.config({ monaco });

export { Editor, DiffEditor } from '@monaco-editor/react';
