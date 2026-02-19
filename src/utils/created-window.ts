// This module compiles selector-based created-at filters into deterministic UTC millisecond windows.

import type { CreatedAtRelativeWindow, LinkSelector } from '../types/domain.js';
import { AppError } from './errors.js';

interface LocalDateTimeParts {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
  millisecond: number;
}

export interface CompiledCreatedWindow {
  fromMs?: number;
  toMs?: number;
  timeZone: string;
  warnings: string[];
}

const DATE_ONLY_REGEX = /^\d{4}-\d{2}-\d{2}$/;
const FALLBACK_TIME_ZONE = 'Europe/Berlin';
const MS_PER_DAY = 24 * 60 * 60 * 1000;

// This cache stores Intl formatters so repeated timezone conversions stay efficient.
const zonedPartsFormatterCache = new Map<string, Intl.DateTimeFormat>();
const offsetFormatterCache = new Map<string, Intl.DateTimeFormat>();

// This helper validates one IANA timezone against the current runtime.
function isValidTimeZone(value: string): boolean {
  try {
    Intl.DateTimeFormat('en-US', { timeZone: value });
    return true;
  } catch {
    return false;
  }
}

// This helper returns a formatter that exposes date-time parts in one specific timezone.
function getZonedPartsFormatter(timeZone: string): Intl.DateTimeFormat {
  const cached = zonedPartsFormatterCache.get(timeZone);
  if (cached) {
    return cached;
  }

  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
  zonedPartsFormatterCache.set(timeZone, formatter);
  return formatter;
}

// This helper returns a formatter that exposes a parseable GMT offset for one timezone.
function getOffsetFormatter(timeZone: string): Intl.DateTimeFormat {
  const cached = offsetFormatterCache.get(timeZone);
  if (cached) {
    return cached;
  }

  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone,
    timeZoneName: 'shortOffset',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
  offsetFormatterCache.set(timeZone, formatter);
  return formatter;
}

// This helper extracts deterministic local date-time parts for one UTC timestamp in one timezone.
function getZonedDateTimeParts(timeZone: string, utcMs: number): LocalDateTimeParts {
  const formatter = getZonedPartsFormatter(timeZone);
  const parts = formatter.formatToParts(new Date(utcMs));
  const byType = new Map<string, string>();

  for (const part of parts) {
    byType.set(part.type, part.value);
  }

  return {
    year: Number(byType.get('year') ?? '0'),
    month: Number(byType.get('month') ?? '0'),
    day: Number(byType.get('day') ?? '0'),
    hour: Number(byType.get('hour') ?? '0'),
    minute: Number(byType.get('minute') ?? '0'),
    second: Number(byType.get('second') ?? '0'),
    millisecond: new Date(utcMs).getUTCMilliseconds()
  };
}

// This helper parses timezone offsets from Intl shortOffset output such as GMT+1 or GMT+01:00.
function parseOffsetMs(offsetValue: string): number {
  const normalized = offsetValue.replace('UTC', 'GMT');
  const match = normalized.match(/^GMT([+-])(\d{1,2})(?::?(\d{2}))?$/);
  if (!match) {
    return 0;
  }

  const sign = match[1] === '-' ? -1 : 1;
  const hours = Number(match[2] ?? '0');
  const minutes = Number(match[3] ?? '0');
  return sign * (hours * 60 + minutes) * 60 * 1000;
}

// This helper returns the timezone offset in milliseconds for one UTC timestamp.
function getTimeZoneOffsetMs(timeZone: string, utcMs: number): number {
  const formatter = getOffsetFormatter(timeZone);
  const parts = formatter.formatToParts(new Date(utcMs));
  const offsetPart = parts.find((part) => part.type === 'timeZoneName')?.value ?? 'GMT';
  return parseOffsetMs(offsetPart);
}

// This helper converts local date-time parts in one timezone to an absolute UTC timestamp.
function localDateTimeToUtcMs(timeZone: string, localParts: LocalDateTimeParts): number {
  const utcLike = Date.UTC(
    localParts.year,
    localParts.month - 1,
    localParts.day,
    localParts.hour,
    localParts.minute,
    localParts.second,
    localParts.millisecond
  );
  let candidate = utcLike;

  // This iterative refinement stabilizes conversion around DST transitions.
  for (let index = 0; index < 4; index += 1) {
    const offsetMs = getTimeZoneOffsetMs(timeZone, candidate);
    const refined = utcLike - offsetMs;
    if (Math.abs(refined - candidate) < 1) {
      return refined;
    }
    candidate = refined;
  }

  return candidate;
}

// This helper shifts one local date-time by a relative unit while preserving calendar semantics.
function shiftLocalDateTime(parts: LocalDateTimeParts, relative: CreatedAtRelativeWindow): LocalDateTimeParts {
  const date = new Date(
    Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second, parts.millisecond)
  );

  if (relative.unit === 'day') {
    date.setUTCDate(date.getUTCDate() + relative.amount);
  } else if (relative.unit === 'week') {
    date.setUTCDate(date.getUTCDate() + relative.amount * 7);
  } else if (relative.unit === 'month') {
    date.setUTCMonth(date.getUTCMonth() + relative.amount);
  } else {
    date.setUTCFullYear(date.getUTCFullYear() + relative.amount);
  }

  return {
    year: date.getUTCFullYear(),
    month: date.getUTCMonth() + 1,
    day: date.getUTCDate(),
    hour: date.getUTCHours(),
    minute: date.getUTCMinutes(),
    second: date.getUTCSeconds(),
    millisecond: date.getUTCMilliseconds()
  };
}

// This helper computes the start of the current day/week/month/year in local timezone parts.
function startOfCurrentUnit(parts: LocalDateTimeParts, unit: CreatedAtRelativeWindow['unit']): LocalDateTimeParts {
  const dayStart: LocalDateTimeParts = {
    year: parts.year,
    month: parts.month,
    day: parts.day,
    hour: 0,
    minute: 0,
    second: 0,
    millisecond: 0
  };

  if (unit === 'day') {
    return dayStart;
  }

  if (unit === 'week') {
    const weekday = new Date(Date.UTC(parts.year, parts.month - 1, parts.day)).getUTCDay();
    const daysSinceMonday = (weekday + 6) % 7;
    return shiftLocalDateTime(dayStart, {
      amount: -daysSinceMonday,
      unit: 'day',
      mode: 'previous_calendar'
    });
  }

  if (unit === 'month') {
    return {
      year: parts.year,
      month: parts.month,
      day: 1,
      hour: 0,
      minute: 0,
      second: 0,
      millisecond: 0
    };
  }

  return {
    year: parts.year,
    month: 1,
    day: 1,
    hour: 0,
    minute: 0,
    second: 0,
    millisecond: 0
  };
}

// This helper parses date-only strings and validates calendar correctness.
function parseDateOnly(value: string): { year: number; month: number; day: number } | null {
  if (!DATE_ONLY_REGEX.test(value)) {
    return null;
  }

  const [yearRaw, monthRaw, dayRaw] = value.split('-');
  const year = Number(yearRaw);
  const month = Number(monthRaw);
  const day = Number(dayRaw);
  const probe = new Date(Date.UTC(year, month - 1, day));

  if (
    probe.getUTCFullYear() !== year ||
    probe.getUTCMonth() + 1 !== month ||
    probe.getUTCDate() !== day
  ) {
    return null;
  }

  return { year, month, day };
}

// This helper converts one absolute bound string into UTC milliseconds with timezone-aware date-only semantics.
function parseAbsoluteBoundary(value: string, timeZone: string, edge: 'start' | 'end'): number {
  const trimmed = value.trim();
  const dateOnly = parseDateOnly(trimmed);

  if (dateOnly) {
    return localDateTimeToUtcMs(timeZone, {
      year: dateOnly.year,
      month: dateOnly.month,
      day: dateOnly.day,
      hour: edge === 'start' ? 0 : 23,
      minute: edge === 'start' ? 0 : 59,
      second: edge === 'start' ? 0 : 59,
      millisecond: edge === 'start' ? 0 : 999
    });
  }

  const parsed = Date.parse(trimmed);
  if (!Number.isFinite(parsed)) {
    throw new AppError(400, 'validation_error', `Invalid timestamp value: ${value}`);
  }

  return parsed;
}

// This helper resolves the effective timezone from selector/user/server/default precedence.
export function resolveEffectiveTimeZone(
  selectorTimeZone: string | null | undefined,
  userTimeZone: string | null | undefined,
  serverDefaultTimeZone: string | null | undefined
): string {
  const candidates = [selectorTimeZone, userTimeZone, serverDefaultTimeZone, FALLBACK_TIME_ZONE];

  for (const candidate of candidates) {
    const normalized = typeof candidate === 'string' ? candidate.trim() : '';
    if (normalized.length === 0) {
      continue;
    }
    if (isValidTimeZone(normalized)) {
      return normalized;
    }
  }

  return FALLBACK_TIME_ZONE;
}

// This helper compiles selector time filters into one deterministic UTC created-at window.
export function compileCreatedWindow(input: {
  selector?: Pick<LinkSelector, 'createdAtFrom' | 'createdAtTo' | 'createdAtRelative' | 'timeZone'>;
  userTimeZone?: string | null;
  serverDefaultTimeZone?: string | null;
  now?: Date;
}): CompiledCreatedWindow {
  const selector = input.selector;
  const now = input.now ?? new Date();
  const warnings: string[] = [];

  const effectiveTimeZone = resolveEffectiveTimeZone(
    selector?.timeZone,
    input.userTimeZone,
    input.serverDefaultTimeZone
  );

  // This warning explains when a requested timezone is invalid and therefore ignored.
  if (selector?.timeZone && selector.timeZone.trim().length > 0 && !isValidTimeZone(selector.timeZone.trim())) {
    warnings.push(
      `selector.timeZone "${selector.timeZone}" is invalid and was replaced with "${effectiveTimeZone}".`
    );
  }

  // This branch preserves deterministic defaults when no created-at filtering is requested.
  if (!selector?.createdAtFrom && !selector?.createdAtTo && !selector?.createdAtRelative) {
    return {
      timeZone: effectiveTimeZone,
      warnings
    };
  }

  let fromMs: number | undefined;
  let toMs: number | undefined;

  if (selector.createdAtRelative) {
    const localNow = getZonedDateTimeParts(effectiveTimeZone, now.getTime());
    if (selector.createdAtRelative.mode === 'rolling') {
      toMs = now.getTime();

      if (selector.createdAtRelative.unit === 'day') {
        fromMs = now.getTime() - selector.createdAtRelative.amount * MS_PER_DAY;
      } else if (selector.createdAtRelative.unit === 'week') {
        fromMs = now.getTime() - selector.createdAtRelative.amount * 7 * MS_PER_DAY;
      } else {
        const shifted = shiftLocalDateTime(localNow, {
          ...selector.createdAtRelative,
          amount: -selector.createdAtRelative.amount
        });
        fromMs = localDateTimeToUtcMs(effectiveTimeZone, shifted);
      }
    } else {
      const startCurrentUnit = startOfCurrentUnit(localNow, selector.createdAtRelative.unit);
      const previousStart = shiftLocalDateTime(startCurrentUnit, {
        ...selector.createdAtRelative,
        amount: -selector.createdAtRelative.amount
      });
      const endExclusive = localDateTimeToUtcMs(effectiveTimeZone, startCurrentUnit);
      fromMs = localDateTimeToUtcMs(effectiveTimeZone, previousStart);
      toMs = endExclusive - 1;
    }
  } else {
    if (selector.createdAtFrom) {
      fromMs = parseAbsoluteBoundary(selector.createdAtFrom, effectiveTimeZone, 'start');
    }
    if (selector.createdAtTo) {
      toMs = parseAbsoluteBoundary(selector.createdAtTo, effectiveTimeZone, 'end');
    }
  }

  // This guard enforces sane inclusive windows after all parsing and relative expansion steps.
  if (typeof fromMs === 'number' && typeof toMs === 'number' && fromMs > toMs) {
    throw new AppError(400, 'validation_error', 'createdAtFrom must be less than or equal to createdAtTo.');
  }

  return {
    fromMs,
    toMs,
    timeZone: effectiveTimeZone,
    warnings
  };
}
