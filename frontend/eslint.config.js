// Only the React hooks rules: the order of hooks and complete effect
// dependencies. TypeScript itself (tsc --noEmit) checks the rest.
// react-hooks 7's React Compiler rules (set-state-in-effect, refs, purity,
// preserve-manual-memoization) stay off: the app doesn't use the compiler,
// and most of their fixes would change behaviour (M29: 58 hits in 33 files).
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';

export default [
  { ignores: ['dist/**', 'node_modules/**'] },
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: { parser: tseslint.parser },
    plugins: { 'react-hooks': reactHooks },
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    rules: {
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'error',
    },
  },
];
