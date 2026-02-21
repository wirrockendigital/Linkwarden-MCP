// This test suite verifies periodic schedule evaluation for the 404-monitor routine.

import { describe, expect, it } from 'vitest';
import { evaluateLink404MonitorSchedule } from '../src/services/link-404-routine.js';
import type { Link404MonitorSettings } from '../src/types/domain.js';

// This helper creates a baseline settings object for deterministic schedule assertions.
function buildSettings(overrides?: Partial<Link404MonitorSettings>): Link404MonitorSettings {
  return {
    userId: 1,
    enabled: true,
    interval: 'monthly',
    toDeleteAfter: 'after_1_year',
    lastRunAt: '2026-01-31T10:00:00.000Z',
    lastStatus: null,
    lastError: null,
    updatedAt: '2026-01-31T10:00:00.000Z',
    ...(overrides ?? {})
  };
}

describe('link 404 routine schedule', () => {
  it('returns not-due for disabled monitor', () => {
    const schedule = evaluateLink404MonitorSchedule(
      buildSettings({
        enabled: false
      }),
      new Date('2026-03-01T10:00:00.000Z')
    );
    expect(schedule.due).toBe(false);
    expect(schedule.nextDueAt).toBeNull();
  });

  it('is due immediately when no previous run exists', () => {
    const now = new Date('2026-03-01T10:00:00.000Z');
    const schedule = evaluateLink404MonitorSchedule(
      buildSettings({
        lastRunAt: null
      }),
      now
    );
    expect(schedule.due).toBe(true);
    expect(schedule.nextDueAt).toBe(now.toISOString());
  });

  it('keeps monthly schedule calendar-aware for month-end runs', () => {
    const schedule = evaluateLink404MonitorSchedule(
      buildSettings({
        interval: 'monthly',
        lastRunAt: '2026-01-31T10:00:00.000Z'
      }),
      new Date('2026-02-28T09:59:59.000Z')
    );
    expect(schedule.due).toBe(false);
    expect(schedule.nextDueAt).toBe('2026-02-28T10:00:00.000Z');
  });

  it('handles semiannual and yearly intervals deterministically', () => {
    const semiannual = evaluateLink404MonitorSchedule(
      buildSettings({
        interval: 'semiannual',
        lastRunAt: '2026-01-15T00:00:00.000Z'
      }),
      new Date('2026-07-15T00:00:00.000Z')
    );
    expect(semiannual.due).toBe(true);
    expect(semiannual.nextDueAt).toBe('2026-07-15T00:00:00.000Z');

    const yearly = evaluateLink404MonitorSchedule(
      buildSettings({
        interval: 'yearly',
        lastRunAt: '2026-03-10T12:00:00.000Z'
      }),
      new Date('2027-03-10T11:59:59.000Z')
    );
    expect(yearly.due).toBe(false);
    expect(yearly.nextDueAt).toBe('2027-03-10T12:00:00.000Z');
  });
});
