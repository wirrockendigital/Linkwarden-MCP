// This module computes deterministic dry-run reorganization plans without mutating remote data.

import type { LinkItem, PlanItem, PlanSummary, PlanStrategy } from '../types/domain.js';

export interface ReorgComputation {
  items: PlanItem[];
  summary: PlanSummary;
  warnings: string[];
}

// This helper converts tag arrays into a sorted unique number list for stable comparisons.
function normalizeTagIds(tags: Array<number | undefined | null>): number[] {
  return [...new Set(tags.filter((tagId): tagId is number => Number.isFinite(tagId as number)))].sort(
    (a, b) => a - b
  );
}

// This helper reads current tag ids from a link item in a deterministic order.
function currentTagIds(link: LinkItem): number[] {
  return normalizeTagIds(link.tags.map((tag) => tag.id));
}

// This helper creates a shared before/after snapshot for plan item persistence and audit readability.
function makeState(link: LinkItem, tagIds: number[], collectionId: number | null): Record<string, unknown> {
  return {
    linkId: link.id,
    tagIds,
    collectionId
  };
}

// This strategy adds tags to links when keyword rules match title, description, or URL text.
function computeTagByKeywords(links: LinkItem[], parameters: Record<string, unknown>): ReorgComputation {
  const rawRules = (parameters.keywordTagRules ?? parameters.rules ?? []) as Array<{
    keywords?: string[];
    tagId?: number;
  }>;

  const rules = rawRules
    .filter((rule) => rule && Array.isArray(rule.keywords) && Number.isFinite(rule.tagId))
    .map((rule) => ({
      keywords: rule.keywords!.map((keyword) => String(keyword).toLowerCase().trim()).filter(Boolean),
      tagId: Number(rule.tagId)
    }))
    .filter((rule) => rule.keywords.length > 0);

  const warnings: string[] = [];
  if (rules.length === 0) {
    warnings.push('No valid keyword tag rules were provided.');
  }

  const items: PlanItem[] = [];

  for (const link of links) {
    const haystack = `${link.title} ${link.description ?? ''} ${link.url}`.toLowerCase();
    const matchedTagIds = new Set<number>();

    for (const rule of rules) {
      if (rule.keywords.some((keyword) => haystack.includes(keyword))) {
        matchedTagIds.add(rule.tagId);
      }
    }

    if (matchedTagIds.size > 1) {
      warnings.push(`Link ${link.id} matched multiple keyword rules; all matched tags will be added.`);
    }

    const beforeTags = currentTagIds(link);
    const afterTags = normalizeTagIds([...beforeTags, ...matchedTagIds]);

    if (JSON.stringify(beforeTags) !== JSON.stringify(afterTags)) {
      items.push({
        linkId: link.id,
        action: 'update-tags',
        before: makeState(link, beforeTags, link.collection?.id ?? null),
        after: makeState(link, afterTags, link.collection?.id ?? null)
      });
    }
  }

  return {
    items,
    summary: {
      scanned: links.length,
      changes: items.length,
      unchanged: links.length - items.length
    },
    warnings: [...new Set(warnings)]
  };
}

// This strategy proposes moving all scoped links into one target collection.
function computeMoveToCollection(links: LinkItem[], parameters: Record<string, unknown>): ReorgComputation {
  const targetCollectionId = Number(parameters.targetCollectionId);
  const warnings: string[] = [];

  if (!Number.isFinite(targetCollectionId)) {
    warnings.push('targetCollectionId is missing or invalid.');
  }

  const items: PlanItem[] = [];

  for (const link of links) {
    const currentCollectionId = link.collection?.id ?? null;
    if (Number.isFinite(targetCollectionId) && currentCollectionId !== targetCollectionId) {
      const tags = currentTagIds(link);
      items.push({
        linkId: link.id,
        action: 'move-collection',
        before: makeState(link, tags, currentCollectionId),
        after: makeState(link, tags, targetCollectionId)
      });
    }
  }

  return {
    items,
    summary: {
      scanned: links.length,
      changes: items.length,
      unchanged: links.length - items.length
    },
    warnings
  };
}

// This strategy replaces tag ids by explicit from->to mappings.
function computeRenameTags(links: LinkItem[], parameters: Record<string, unknown>): ReorgComputation {
  const rawMap = (parameters.renameMap ?? []) as Array<{ fromTagId?: number; toTagId?: number }>;
  const mapping = new Map<number, number>();

  for (const entry of rawMap) {
    if (Number.isFinite(entry.fromTagId) && Number.isFinite(entry.toTagId)) {
      mapping.set(Number(entry.fromTagId), Number(entry.toTagId));
    }
  }

  const warnings: string[] = [];
  if (mapping.size === 0) {
    warnings.push('renameMap does not contain valid fromTagId/toTagId mappings.');
  }

  const items: PlanItem[] = [];

  for (const link of links) {
    const beforeTags = currentTagIds(link);
    const afterTags = normalizeTagIds(beforeTags.map((tagId) => mapping.get(tagId) ?? tagId));

    if (JSON.stringify(beforeTags) !== JSON.stringify(afterTags)) {
      items.push({
        linkId: link.id,
        action: 'rename-tags',
        before: makeState(link, beforeTags, link.collection?.id ?? null),
        after: makeState(link, afterTags, link.collection?.id ?? null)
      });
    }
  }

  return {
    items,
    summary: {
      scanned: links.length,
      changes: items.length,
      unchanged: links.length - items.length
    },
    warnings
  };
}

// This strategy collapses duplicate tags into canonical tags based on explicit groups.
function computeDedupeTags(links: LinkItem[], parameters: Record<string, unknown>): ReorgComputation {
  const groups = (parameters.groups ?? parameters.canonicalByName ?? []) as Array<{
    canonicalTagId?: number;
    duplicateTagIds?: number[];
  }>;

  const replacementMap = new Map<number, number>();
  const warnings: string[] = [];

  for (const group of groups) {
    if (!Number.isFinite(group.canonicalTagId) || !Array.isArray(group.duplicateTagIds)) {
      continue;
    }

    for (const duplicateId of group.duplicateTagIds) {
      if (Number.isFinite(duplicateId)) {
        replacementMap.set(Number(duplicateId), Number(group.canonicalTagId));
      }
    }
  }

  if (replacementMap.size === 0) {
    warnings.push('No valid dedupe groups were provided.');
  }

  const items: PlanItem[] = [];

  for (const link of links) {
    const beforeTags = currentTagIds(link);
    const afterTags = normalizeTagIds(beforeTags.map((tagId) => replacementMap.get(tagId) ?? tagId));

    if (JSON.stringify(beforeTags) !== JSON.stringify(afterTags)) {
      items.push({
        linkId: link.id,
        action: 'dedupe-tags',
        before: makeState(link, beforeTags, link.collection?.id ?? null),
        after: makeState(link, afterTags, link.collection?.id ?? null)
      });
    }
  }

  return {
    items,
    summary: {
      scanned: links.length,
      changes: items.length,
      unchanged: links.length - items.length
    },
    warnings
  };
}

// This dispatcher runs exactly one strategy and always returns deterministic ordering.
export function computeReorgPlan(
  strategy: PlanStrategy,
  parameters: Record<string, unknown>,
  links: LinkItem[]
): ReorgComputation {
  const sortedLinks = [...links].sort((a, b) => a.id - b.id);

  switch (strategy) {
    case 'tag-by-keywords':
      return computeTagByKeywords(sortedLinks, parameters);
    case 'move-to-collection':
      return computeMoveToCollection(sortedLinks, parameters);
    case 'rename-tags':
      return computeRenameTags(sortedLinks, parameters);
    case 'dedupe-tags':
      return computeDedupeTags(sortedLinks, parameters);
    default:
      return {
        items: [],
        summary: {
          scanned: sortedLinks.length,
          changes: 0,
          unchanged: sortedLinks.length
        },
        warnings: [`Unsupported strategy: ${strategy}`]
      };
  }
}
