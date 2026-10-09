import axe from 'axe-core';
import { expect } from 'vitest';

/**
 * Runs axe-core on a rendered container and fails with a readable list of
 * violations. Color contrast is skipped here (jsdom has no layout / computed
 * colors); it is checked in the real-browser scan instead.
 */
export async function expectNoA11yViolations(container: Element) {
  const results = await axe.run(container, {
    rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
  });
  const report = results.violations.map(
    (v) => `${v.id} (${v.impact}): ${v.help}\n  ${v.nodes.map((n) => n.html).join('\n  ')}`,
  );
  expect(report, report.join('\n')).toEqual([]);
}
