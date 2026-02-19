// This test suite verifies deterministic timezone-aware created-at window compilation.

import { describe, expect, it } from 'vitest';
import { compileCreatedWindow, resolveEffectiveTimeZone } from '../src/utils/created-window.js';
import { AppError } from '../src/utils/errors.js';

describe('created window compiler', () => {
  it('resolves effective timezone with selector -> user -> server -> default precedence', () => {
    expect(resolveEffectiveTimeZone('Europe/Berlin', 'UTC', 'America/New_York')).toBe('Europe/Berlin');
    expect(resolveEffectiveTimeZone(undefined, 'UTC', 'America/New_York')).toBe('UTC');
    expect(resolveEffectiveTimeZone(undefined, undefined, 'America/New_York')).toBe('America/New_York');
    expect(resolveEffectiveTimeZone('Invalid/Timezone', null, null)).toBe('Europe/Berlin');
  });

  it('compiles absolute date-only bounds as inclusive local day windows', () => {
    const compiled = compileCreatedWindow({
      selector: {
        createdAtFrom: '2026-01-01',
        createdAtTo: '2026-01-31',
        timeZone: 'Europe/Berlin'
      },
      now: new Date('2026-02-17T10:00:00.000Z')
    });

    expect(compiled.fromMs).toBe(Date.parse('2025-12-31T23:00:00.000Z'));
    expect(compiled.toMs).toBe(Date.parse('2026-01-31T22:59:59.999Z'));
  });

  it('compiles previous_calendar month windows from timezone-local calendar boundaries', () => {
    const compiled = compileCreatedWindow({
      selector: {
        createdAtRelative: {
          amount: 1,
          unit: 'month',
          mode: 'previous_calendar'
        },
        timeZone: 'Europe/Berlin'
      },
      now: new Date('2026-02-17T10:00:00.000Z')
    });

    expect(compiled.fromMs).toBe(Date.parse('2025-12-31T23:00:00.000Z'));
    expect(compiled.toMs).toBe(Date.parse('2026-01-31T22:59:59.999Z'));
  });

  it('compiles rolling day windows relative to the current timestamp', () => {
    const now = new Date('2026-02-17T10:00:00.000Z');
    const compiled = compileCreatedWindow({
      selector: {
        createdAtRelative: {
          amount: 30,
          unit: 'day',
          mode: 'rolling'
        }
      },
      now
    });

    expect(compiled.toMs).toBe(now.getTime());
    expect(compiled.fromMs).toBe(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  });

  it('rejects absolute windows where from is greater than to', () => {
    expect(() =>
      compileCreatedWindow({
        selector: {
          createdAtFrom: '2026-02-01',
          createdAtTo: '2026-01-01',
          timeZone: 'Europe/Berlin'
        }
      })
    ).toThrow(AppError);
  });
});
