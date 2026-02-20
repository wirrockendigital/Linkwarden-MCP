// This test suite validates the admin UI IA refactor contracts against rendered dashboard HTML.

import { describe, expect, it } from 'vitest';
import { renderDashboardPage } from '../src/http/ui.js';
import type { SessionPrincipal } from '../src/types/domain.js';

function makePrincipal(role: 'admin' | 'user'): SessionPrincipal {
  return {
    userId: role === 'admin' ? 1 : 2,
    username: role === 'admin' ? 'admin-user' : 'normal-user',
    role,
    sessionId: role === 'admin' ? 'sess-admin' : 'sess-user'
  };
}

describe('admin ui ia refactor contracts', () => {
  it('renders role-aware tab shell and keeps deep-link utility contract in script output', () => {
    const html = renderDashboardPage(makePrincipal('user'), 'csrf-token');

    expect(html).toContain('id="topTabsNav" role="tablist"');
    expect(html).toContain('id="subTabsNav" role="tablist"');
    expect(html).toContain('function parseTabState()');
    expect(html).toContain('function serializeTabState(topTab, subTab)');
    expect(html).toContain("params.set('tab', topTab)");
    expect(html).toContain("params.set('sub', subTab)");
  });

  it('keeps admin-only panels hidden from user render output and present for admin', () => {
    const userHtml = renderDashboardPage(makePrincipal('user'), 'csrf-token');
    const adminHtml = renderDashboardPage(makePrincipal('admin'), 'csrf-token');

    expect(userHtml).not.toContain('data-top-tab="administration"');
    expect(userHtml).not.toContain('id="usersResult"');

    expect(adminHtml).toContain('data-top-tab="administration" data-sub-tab="benutzer"');
    expect(adminHtml).toContain('data-top-tab="administration" data-sub-tab="admin-keys"');
    expect(adminHtml).toContain('id="usersResult"');
  });

  it('keeps lazy-load dedupe and partial-refresh orchestration contracts in rendered script', () => {
    const html = renderDashboardPage(makePrincipal('admin'), 'csrf-token');

    expect(html).toContain('const inflightRequests = new Map();');
    expect(html).toContain('const inflightPanelLoads = new Map();');
    expect(html).toContain('const mutationInvalidationMap = {');
    expect(html).toContain('function requestJson(url, options = {})');
    expect(html).toContain('function ensurePanelLoaded(topTab, subTab, options = {})');
    expect(html).toContain('function invalidateAfterMutation(actionKey)');
  });

  it('keeps section-level dirty guard and mutation section clearing in rendered script', () => {
    const html = renderDashboardPage(makePrincipal('admin'), 'csrf-token');

    expect(html).toContain('data-form-section=');
    expect(html).toContain('const sectionRegistry = new Map();');
    expect(html).toContain('const dirtySections = new Set();');
    expect(html).toContain('function resolveSectionFromControl(control)');
    expect(html).toContain('function getDirtySectionsForPanel(topTab, subTab)');
    expect(html).toContain('Du hast ungespeicherte Änderungen in:');
    expect(html).toContain('mutationSections: [');
  });

  it('keeps feedback and a11y contracts in rendered output', () => {
    const html = renderDashboardPage(makePrincipal('admin'), 'csrf-token');

    expect(html).toContain('id="statusOverview" aria-live="polite"');
    expect(html).toContain('id="toastStack" class="toast-stack" aria-live="polite"');
    expect(html).toContain('function showToast(type, message, options = {})');
    expect(html).toContain('function showFieldError(control, message)');
    expect(html).toContain('function openDebugDrawer(payload, options = {})');
    expect(html).toContain('openDebugDrawer(json, { autoOpenOnError: !res.ok })');
    expect(html).toContain("showToast('error', message)");
    expect(html).toContain("showToast('success', successMessage");
    expect(html).toContain('aria-controls');
    expect(html).toContain('aria-labelledby');
  });

  it('keeps keyboard tab interaction hooks and legacy handlers in rendered script', () => {
    const html = renderDashboardPage(makePrincipal('admin'), 'csrf-token');

    expect(html).toContain("key === 'ArrowRight'");
    expect(html).toContain("key === 'ArrowLeft'");
    expect(html).toContain("key === 'Home'");
    expect(html).toContain("key === 'End'");
    expect(html).toContain("key === 'Enter'");
    expect(html).toContain("key === ' ' || key === 'Spacebar'");

    const stableHandlers = [
      'loadUsers',
      'createUser',
      'setUserActive',
      'setUserWriteMode',
      'setUserOfflinePolicy',
      'setTaggingPolicy',
      'setUserTaggingPreferences',
      'issueAdminKey',
      'revokeAdminKey',
      'setUserLinkwardenToken',
      'updateLinkwardenConfig',
      'setOwnTaggingPreferences',
      'setOwnNewLinksRoutine',
      'setOwnChatControl',
      'setOwnLinkwardenToken',
      'issueOwnKey',
      'revokeOwnKey'
    ];

    for (const handler of stableHandlers) {
      expect(html).toContain(`function ${handler}(`);
    }
  });
});
