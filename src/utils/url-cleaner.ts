// This module removes tracking parameters from URLs while preserving stable destination paths.

export interface CleanTrackedUrlOptions {
  removeUtm: boolean;
  removeKnownTracking: boolean;
  keepParams: string[];
  extraTrackingParams: string[];
}

export interface CleanTrackedUrlResult {
  cleanedUrl: string;
  changed: boolean;
  removedParams: string[];
}

// This set defines broadly-used tracking parameters that can be stripped safely in most automation flows.
const DEFAULT_TRACKING_PARAM_NAMES = new Set<string>([
  'fbclid',
  'gclid',
  'dclid',
  'gbraid',
  'wbraid',
  'msclkid',
  'yclid',
  'mc_cid',
  'mc_eid',
  'mkt_tok',
  'igshid',
  'srsltid',
  'vero_id',
  'vero_conv',
  'oly_anon_id',
  'oly_enc_id',
  'wickedid',
  'ref_src',
  'ref_url'
]);

// This helper normalizes parameter names for case-insensitive comparisons.
function normalizeParamName(input: string): string {
  return input.trim().toLocaleLowerCase();
}

// This helper decides whether one query parameter should be removed according to cleaning options.
function shouldRemoveParam(
  normalizedParamName: string,
  options: CleanTrackedUrlOptions,
  keepSet: Set<string>,
  extraTrackingSet: Set<string>
): boolean {
  if (keepSet.has(normalizedParamName)) {
    return false;
  }

  if (options.removeUtm && normalizedParamName.startsWith('utm_')) {
    return true;
  }

  if (extraTrackingSet.has(normalizedParamName)) {
    return true;
  }

  if (options.removeKnownTracking && DEFAULT_TRACKING_PARAM_NAMES.has(normalizedParamName)) {
    return true;
  }

  return false;
}

// This function removes tracking parameters from one absolute URL and reports exactly what changed.
export function cleanTrackedUrl(urlInput: string, options: CleanTrackedUrlOptions): CleanTrackedUrlResult {
  const url = new URL(urlInput);
  const keepSet = new Set(options.keepParams.map((paramName) => normalizeParamName(paramName)));
  const extraTrackingSet = new Set(options.extraTrackingParams.map((paramName) => normalizeParamName(paramName)));
  const nextParams = new URLSearchParams();
  const removedParams: string[] = [];

  for (const [name, value] of url.searchParams.entries()) {
    const normalized = normalizeParamName(name);
    if (shouldRemoveParam(normalized, options, keepSet, extraTrackingSet)) {
      removedParams.push(name);
      continue;
    }

    nextParams.append(name, value);
  }

  const nextSearch = nextParams.toString();
  url.search = nextSearch.length > 0 ? `?${nextSearch}` : '';

  return {
    cleanedUrl: url.toString(),
    changed: removedParams.length > 0,
    removedParams
  };
}
