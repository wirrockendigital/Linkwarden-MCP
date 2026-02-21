# Milestones

## 2026-02-20

1. Extended `user_chat_control` with chat-link capture tagging controls: `chat_capture_tag_name` (default `AI Chat`), `chat_capture_tag_ai_chat_enabled` (default `true`), and `chat_capture_tag_ai_name_enabled` (default `true`), including migration coverage for existing SQLite databases.
2. Extended domain/store contracts for chat-control (`UserChatControlSettings`, `getUserChatControlSettings`, `setUserChatControlSettings`) with deterministic normalization for chat capture tag defaults and toggle persistence.
3. Extended `/admin/ui/user/chat-control` payload schema and dashboard form with `Chat-Link-Tag-Name`, `AI Chat-Tag setzen`, and `AI Name-Tag setzen`.
4. Added new MCP tool `linkwarden_capture_chat_links` with flexible input (`urls[]` or `chatText`), deterministic hierarchy resolution (`AI Chats -> <AI Name> -> <Chat Name>`), target-collection dedupe, optional dry-run, and idempotency support.
5. Implemented chat-link capture tagging behavior with two independent user toggles: static tag (`AI Chat` configurable) and dynamic AI-name tag (for example `ChatGPT`), both enabled by default.
6. Added chat-link capture audit logging including resolved collection ids, created collections, applied tags, and detected/created/failed counters.
7. Added regression tests in `test/capture-chat-links.test.ts` covering hierarchy auto-create, deterministic multi-match selection, dedupe behavior, write-mode gating, per-link failure handling, and tag toggle combinations.
8. Extended schema and store tests (`test/tool-schema-safety.test.ts`, `test/chat-control-store.test.ts`) for the new MCP tool and chat-control defaults/toggles.
9. Updated documentation (`README.md`, `docs/03-setup-und-betrieb.md`, `docs/05-mcp-tools.md`) for the new chat-link capture workflow and per-user tag toggles.
10. Bumped package/server version metadata to `0.2.18` (`package.json`, `package-lock.json`, `src/version.ts`) for the chat-link capture + admin IA iteration.

## 2026-02-17

1. Executed alpha API reset without secondary naming schema: replaced MCP tool surface with final native tool names only (no parallel legacy tool namespace in discovery).
2. Replaced MCP tool schema registry and `tools/list` metadata with the new 31-tool alpha catalog (`query`, `mutate`, `delete`, rules, saved queries, audit, undo, dedupe, classify, normalize).
3. Rebuilt MCP tool execution layer (`src/mcp/tools.ts`) around standardized response envelopes (`ok`, `data`, `summary`, `paging`, `warnings`, `failures`).
4. Implemented deterministic query snapshots + cursor paging for `linkwarden_query_links` with projection (`fields`) and verbosity levels (`minimal|normal|debug`).
5. Added hard counter/aggregation tools (`linkwarden_get_stats`, `linkwarden_aggregate_links`) for token-efficient overview operations.
6. Implemented selector-based mutation and deletion flows (`linkwarden_mutate_links`, `linkwarden_delete_links`) with dry-run preview and idempotency-key replay protection.
7. Added URL normalization, duplicate detection, and merge flows (`linkwarden_normalize_urls`, `linkwarden_find_duplicates`, `linkwarden_merge_duplicates`).
8. Added rule engine persistence and runtime tools (`linkwarden_create_rule`, `test`, `apply`, `run_rules_now`, `list`, `delete`) including per-user lock usage for run orchestration.
9. Added saved query persistence and execution by id (`linkwarden_create_saved_query`, `list`, `run_saved_query`).
10. Added operation log + operation items persistence and undo support (`linkwarden_get_audit`, `linkwarden_undo_operation`) with before/after snapshots.
11. Extended SQLite schema with new alpha tables: `query_snapshots`, `idempotency_keys`, `rules`, `rule_runs`, `saved_queries`, `operation_log`, `operation_items`.
12. Extended API key schema with optional tool/collection scopes and added scope-aware principal fields (`toolScopes`, `collectionScopes`) consumed by MCP tool authorization checks.
13. Added OAuth scope parsing for tool/collection scope constraints in MCP bearer authentication resolution.
14. Rewrote MCP tools documentation (`docs/05-mcp-tools.md`) to the new alpha catalog and updated README usage examples to new tool names.
15. Bumped package/server version metadata to `0.2.4` (`package.json`, `package-lock.json`, `src/version.ts`) as final alpha target in `0.2.x`.
16. Standardized all tool envelopes to always include `error` (`null` on success) and normalized idempotent cached payloads through the same envelope builder.
17. Tightened write-mode policy by gating `linkwarden_create_rule`, `linkwarden_delete_rule`, and `linkwarden_create_saved_query` behind the same write-mode check as other mutating tools.
18. Removed remaining internal secondary-schema naming by renaming the migration temp table to `users_tmp`.
19. Bumped package/server version metadata to `0.2.5` (`package.json`, `package-lock.json`, `src/version.ts`) for the next alpha patch release.
20. Built and pushed a Synology-compatible multi-arch Docker release to Docker Hub (`docker.io/wirrockendigital/linkwarden-mcp:0.2.5` and `:latest`) for `linux/amd64` and `linux/arm64` with manifest digest `sha256:20e2511ba226ff25cb1131f142aca8e19c136d4057dab3e983bbf098af10c03c`.
21. Executed a comprehensive MCP runtime validation across the active alpha toolset (query/stats/aggregate/get/suggest/find/normalize/mutate/delete/collections/tags/rules/saved queries/audit/undo) using valid payloads and dry-run/write paths where applicable.
22. Collected and reviewed runtime failures from the test round; no reproducible failures were observed in the active `0.2.x` tool paths during this validation run.
23. Bumped package/server version metadata to `0.2.6` (`package.json`, `package-lock.json`, `src/version.ts`) for the post-validation release.
24. Built and pushed a Synology-compatible multi-arch Docker release to Docker Hub (`docker.io/wirrockendigital/linkwarden-mcp:0.2.6` and `:latest`) for `linux/amd64` and `linux/arm64` with manifest digest `sha256:8864e7f6f7c6e7c0bd3a8c6d5828c376c3f63cce1939e44bd831c749e7a9f58b`.
25. Implemented hard-alpha governed tagging cutover: removed overlapping MCP tools `linkwarden_suggest_tags` and `linkwarden_classify_links` from schema registry/tool discovery and introduced `linkwarden_governed_tag_links` as the single native taxonomy-first one-call flow.
26. Added governed tagging policy data model with global admin policy in `app_state` (`global_tagging_policy`) and per-user settings fields `tagging_strictness` + `fetch_mode`, including migration logic for existing SQLite instances.
27. Added persistent governed-tagging working-memory tables `tag_aliases`, `tag_candidates`, and `link_context_cache` with deterministic upsert/query store methods.
28. Added optional fetch context module (`src/utils/link-context-fetch.ts`) with strict timeout/byte limits and sanitized text extraction for token-efficient contextual tagging.
29. Implemented admin/user UI backend routes for governed tagging policy and preferences:
    - `GET/POST /admin/ui/admin/tagging-policy`
    - `GET/POST /admin/ui/user/tagging-preferences`
    - `GET/POST /admin/ui/admin/users/:userId/tagging-preferences`
30. Added dashboard controls for global governed-tagging policy and per-user tagging preferences, including admin-controlled fetch-mode override behavior.
31. Implemented immediate reset behavior when admin disables fetch override by resetting all user `fetch_mode` values to the global admin `fetchMode`.
32. Updated MCP/docs/readme references to the new governed tagging tool and removed legacy/fallback wording from security docs.
33. Bumped package/server version metadata to `0.2.7` (`package.json`, `package-lock.json`, `src/version.ts`) for the governed-tagging hard-alpha release.
34. Built and pushed a Synology-compatible multi-arch Docker release to Docker Hub (`docker.io/wirrockendigital/linkwarden-mcp:0.2.7` and `:latest`) for `linux/amd64` and `linux/arm64`.
35. Verified published manifest index digest `sha256:477657d8d2f642a012b58c144eea6ee34df4c0c53deebecacf3cc19f5f9833f2` for both tags.

## 2026-02-12

1. Initialized greenfield `linkwarden-mcp` TypeScript project structure.
2. Implemented secure encrypted config storage with first-run setup and unlock flow.
3. Added SQLite persistence for state, plans, plan runs, and audit logs.
4. Implemented Linkwarden API client with timeout, retry, backoff, and pagination helpers.
5. Implemented MCP Streamable HTTP JSON-RPC endpoint and full required toolset.
6. Added dry-run planning, explicit apply confirmation, write-mode gating, and audit logging.
7. Added health/readiness routes, Dockerfile, Portainer stack example, and German README.
8. Added unit tests for crypto, planning determinism, auth middleware, and safety schema checks.
9. Added Portainer-first stack deployment with environment-file driven configuration and static IP on allmydocker-net.
10. Standardized Portainer artifact naming to project-based files: linkwarden-mcp.yaml and linkwarden-mcp.env.
11. Split documentation into AGENTS.md (engineering rules) and a user-centered README focused on install/configure/operate on Synology Portainer.
12. Added multi-user MCP authentication with per-user API keys, bootstrap admin token flow, and local admin user/key management endpoints.
13. Removed all legacy authentication compatibility paths and legacy config fields before first production/test rollout.
14. Added structured user and operations documentation in /docs as dedicated Markdown files.
15. Clarified in docs where and how masterPassphrase is configured and used operationally.
16. Added auto-unlock on startup via mounted passphrase file and documented Synology/Portainer configuration.

## 2026-02-13

1. Reworked security model to strict `admin|user` roles with per-user write-mode enforcement in MCP write tools.
2. Implemented browser UI at `GET /` with first-run setup, login, session handling, CSRF protection, and login rate limiting.
3. Added full session-protected admin/user route sets for user management, API key lifecycle, whitelist management, and Linkwarden target updates.
4. Removed legacy passphrase-based admin API bypasses and deprecated global write-mode admin endpoints.
5. Added strict Linkwarden whitelist validation/enforcement for domain/ip/cidr and runtime client creation via validated target + whitelist.
6. Updated readiness behavior to reflect target + whitelist + upstream checks.
7. Updated Portainer env/stack files with session-cookie runtime variables.
8. Added new test coverage for password hashing and whitelist matching/validation, and updated auth/crypto tests for the new model.
9. Rewrote user-facing README and docs to the new UI-first multi-user operation flow.
10. Removed leftover legacy backup artifact (`milestone.root-backup-before-flatten.md`) from the project root.
11. Added GitHub Actions release pipeline for tag-driven multi-arch Docker image build and push (GHCR + optional Docker Hub).
12. Initialized local Git repository for first push to private GitHub repository `Linkwarden-MCP`.
13. Added configurable runtime UID/GID support for Synology NAS via `MCP_RUN_UID` and `MCP_RUN_GID` in Portainer env/stack.
14. Fixed first-run UI script escaping bug in whitelist parsing that prevented the setup button from executing in the browser.
15. Added end-to-end structured debug logging across HTTP lifecycle, setup/auth/UI actions, MCP protocol/tool execution, and Linkwarden upstream API retries/timeouts with strict secret redaction.
16. Added optional host port mapping for Synology/NAS direct access via env (`MCP_HOST_BIND_IP` + uncommon `MCP_HOST_PORT=39227`) while keeping secure local-only default binding.
17. Added per-user Linkwarden API key storage (encrypted), token management UI/paths, and clearer UI labels distinguishing Linkwarden -> MCP vs MCP -> AI, including username-based admin selectors.
18. Added OAuth 2.0 support for ChatGPT MCP connectors with discovery metadata, authorization-code+PKCE flow, token/refresh endpoints, optional static client ID/secret, dynamic client registration, and MCP OAuth bearer validation with API-key legacy fallback.
19. Added OAuth discovery alias endpoints (`/.well-known/openid-configuration` and `/mcp/.well-known/*`) to improve connector compatibility.
20. Added request header diagnostics logging for all endpoints to simplify OAuth discovery debugging.

## 2026-02-14

1. Added connector-compatible MCP wrapper tools `search` and `fetch` while keeping existing `linkwarden_*` tools unchanged.
2. Aligned Linkwarden single-link update calls with documented API semantics by switching from `PATCH /api/v1/links/{id}` to `PUT /api/v1/links/{id}`.
3. Extended test coverage for new connector schemas/tool exposure and added a client-level regression test to enforce `PUT` for `updateLink`.
4. Ensured connector wrappers return stable MCP text content payloads (`results[]` for `search`, document object for `fetch`) using existing per-user Linkwarden auth flow.
5. Moved the browser setup/admin interface to `GET /admin` and updated all UI-auth/session/admin-user routes to the `/admin/...` namespace.
6. Removed Linkwarden whitelist functionality completely from setup flow, runtime client creation, database access layer, tests, and documentation.
7. Added a root OAuth login bridge so `GET /?next=...` safely redirects to `/admin?next=...` while root remains non-UI and MCP-focused.
8. Fixed Linkwarden response parsing compatibility by accepting `response[]` payloads (in addition to `results[]`) and mapping link `name` to MCP `title`.
9. Added resilient search behavior: wildcard (`*`) and empty-query handling now list links via `/api/v1/links`, and empty `/api/v1/search` results now trigger a bounded `/api/v1/links` fallback with local text match.
10. Added regression tests covering `response[]` payload parsing and search fallback from `/api/v1/search` to `/api/v1/links`.
11. Added deep list-based search fallback scanning (up to bounded pages) so connector search still finds links when upstream search indexing is incomplete.
12. Added `linkwarden_capture_chat_links` tool to extract URLs from chat text and store them in `ChatGPT Chats > <Chat Name>` with optional deduplication.
13. Added `linkwarden_monitor_offline_links` tool with persisted per-link health state tracking and optional archival move after configurable offline duration/failure streak thresholds.
14. Added SQLite table `link_health_state` and store methods for monitor state snapshots and archival marks.
15. Added `linkwarden_run_daily_maintenance` orchestration tool to execute reorg planning/apply and offline monitoring/archival in one gated workflow (`apply=true` requires `confirm=APPLY`).
16. Added persistence for maintenance orchestration runs via new SQLite tables `maintenance_runs` and `maintenance_run_items`.
17. Added per-user maintenance run lock handling with TTL-backed lock acquisition/release to prevent concurrent overlapping runs.
18. Extended `linkwarden_run_daily_maintenance` to record run lifecycle, step items, partial failure status, and structured error details.
19. Removed hard MCP link interaction caps by making `limit` optional in key schemas, removing connector search fixed-size behavior, and enabling full-dataset processing when no limit is provided.
20. Removed Linkwarden client fallback scan cap (`maxScannedLinks=2000`) so search fallback can scan all pages and not miss late-offset matches.
21. Removed response truncation in chat-capture and offline-monitor outputs (`created`, `failed`, `checked`, `eligibleLinkIds`) to keep full visibility for large datasets.
22. Added regression coverage to verify fallback search continues beyond offset 2000 and schema parsing supports unlimited mode when `limit` is omitted.
23. Fixed pagination loops to advance by actual returned item count (not requested page size), preventing early stop at 50-item upstream caps and enabling full scans of large libraries.
24. Fixed OAuth `/authorize` compatibility by defaulting missing `resource` to the canonical `/mcp` resource URL instead of hard-failing with `invalid_resource`.
25. Added unit tests for OAuth resource validation covering default behavior, accepted local resources, and foreign resource rejection.
26. Hardened Linkwarden pagination against repeated upstream pages (offset ignored) to prevent wildcard (`*`) full-scan timeouts, added local wildcard offset fallback for capped pages, and added regression tests for both scenarios.
27. Added `paging.warning` diagnostics for search responses when upstream pagination is unreliable and introduced `linkwarden_get_server_info` so AI clients can query MCP server/version/protocol metadata on demand.
28. Fixed wildcard full-scope loading to auto-fallback from high page size to `50` when upstream repeats pages (ignored offset), including page-scan diagnostics (`initial/effective page size`, `pagesScanned`, `fallbackPageSizeApplied`).
29. Added page-level Linkwarden list telemetry logs (`requested limit/offset`, `returned count`, `first/last id`, `total`) to make paging defects directly traceable in runtime logs.
30. Added `loadLinksForScopeDetailed(...)` with warning+diagnostics payload and wired unbounded `linkwarden_search_links` to expose these diagnostics (`paging.warning`, optional `debug.scopeLoad`).
31. Fixed single-link payload parsing by unwrapping wrapper envelopes (`link`, `item`, `result`, `response`, `data`) for `getLink`, `updateLink`, `createLink`, and `createCollection`.
32. Extended MCP schemas for operational debugging/compatibility: `linkwarden_search_links` now accepts `collection_id`/`tag_ids` aliases plus optional `debug`, and `linkwarden_monitor_offline_links` now supports optional `debug`.
33. Added regression tests for (a) adaptive wildcard fallback recovering full result sets when `limit=100` ignores offset but `limit=50` works, and (b) single-link response unwrapping correctness.
34. Bumped project/server version to `0.1.1` and added `GET /version` endpoint so version metadata can be queried both via MCP (`linkwarden_get_server_info`) and plain HTTP (`domain.tld/version`) from the same canonical constants.
35. Added a sustainable paging compatibility fix for large libraries by introducing modern cursor-based `/api/v1/search` scanning (`searchQueryString` + `nextCursor`) with strict local scope filtering and wired `linkwarden_search_links` (bounded + unbounded) to this reliable full-scope loader instead of deprecated offset-only paging.
36. Bumped project/server version to `0.1.2` for the stable paging compatibility release and prepared a new Synology-compatible multi-arch Docker publish (`linux/amd64` + `linux/arm64`) to Docker Hub.
37. Extended version metadata responses so `protocolVersion` now includes a runtime timestamp suffix in format `yyyy-mm-dd - hh-mm-ss` for `/version` and `linkwarden_get_server_info` diagnostics.
38. Bumped project/server version to `0.1.3` to publish the protocolVersion timestamp extension as a new release.

## 2026-02-15

1. Reworked native Linkwarden single-link updates to use `PUT /api/v1/links` with mandatory body field `id` and API-native field mapping (`title -> name`, `tagIds -> tags`).
2. Simplified write execution paths to native per-link updates only by removing tool-side dependence on `bulkReplaceLinks` in `linkwarden_apply_plan`, `linkwarden_bulk_update_links`, and `linkwarden_monitor_offline_links`.
3. Kept update responses deterministic by reloading the link via `getLink(id)` after native write so MCP output shape remains stable across Linkwarden response variants.
4. Updated client regression coverage to enforce the native update body contract (`id`, mapped fields) and verified `lint` + `build` pass after changes.
5. Test execution remains environment-blocked in this sandbox due missing optional module `@rollup/rollup-darwin-arm64` (npm optional dependency resolution issue).
6. Executed live MCP validation against connected Linkwarden and confirmed native totals from tool outputs: `1162` links, `389` collections, `3` tags.
7. Added native `pinned` support end-to-end (search input schema, Linkwarden query forwarding, link payload mapping, MCP output field) so pinned-based counting/filtering works without hidden/ignored parameters.
8. Removed search-time fallback logic from native client/tool paths by making wildcard queries use `/api/v1/links` directly and non-wildcard queries use `/api/v1/search` directly, including native pagination totals.
9. Reworked `loadLinksForScopeDetailed` to native paging modes only (`list_scan`/`search_scan`) and removed cursor/list fallback selection from the active execution path.
10. Replaced fallback-oriented client tests with native behavior tests and added schema test coverage for the new `pinned` input.
11. Fixed deterministic `pinned` behavior for MCP search by forcing full native page scan + local pinned filtering when `pinned` is requested, so `paging.total` reflects filtered results even if upstream ignores `pinned` query params.
12. Defaulted link mapping `pinned` to `false` when upstream omits pin metadata and added scope-level local pinned filtering in `loadLinksForScopeDetailed(...)`.
13. Added regression tests for pinned default mapping and native scope filtering under upstream pinned-filter mismatch conditions.
14. Bumped project/server version to `0.1.4` and prepared a new Synology-compatible multi-arch Docker release (`linux/amd64` + `linux/arm64`) to Docker Hub.
15. Fixed native pagination for scope/search loading by switching deterministic scope scans to `/api/v1/search` cursor traversal (`searchQueryString`, `cursor`, `nextCursor`) with duplicate-page and cursor-cycle guards.
16. Reworked `linkwarden_search_links` to use one deterministic scope load + local slicing for `offset/limit`, so totals remain stable even when upstream `/api/v1/links` offset paging is unreliable.
17. Added regression coverage to ensure repeated cursor pages do not duplicate collected links.
18. Bumped package/server version metadata to `0.1.5` (`package.json`, lockfile, and `src/version.ts`) to prepare a new release.
19. Built and pushed a Synology-compatible multi-arch Docker release to Docker Hub (`docker.io/wirrockendigital/linkwarden-mcp:0.1.5` and `:latest`) with digest `sha256:d84c4a4134a61cd9ee842069e144a5e2ce5dff852eb00aacffc714c6ab3e4121` for `linux/amd64` and `linux/arm64`.
20. Fixed native link updates for current Linkwarden API behavior by switching `updateLink` from `PUT /api/v1/links` to `PUT /api/v1/links/{id}` and mapping write payload fields to object-based structures (`collection: {id}`, `tags: [{id}]`).
21. Updated regression coverage for `updateLink` to assert the new endpoint and payload contract so tag/collection writes no longer regress silently.
22. Added native tag lifecycle support to the Linkwarden client with `createTag(name)` and `deleteTag(id)` using `/api/v1/tags` and `/api/v1/tags/{id}`.
23. Added new MCP tools `linkwarden_create_tag`, `linkwarden_delete_tag`, and `linkwarden_assign_tags` so agents can create/delete tags and assign tags by name with optional auto-create for missing tags.
24. Added schema and regression coverage for the new tag tools (`tool-schemas`, client request-shape tests, and write-mode gate checks) and documented usage examples in MCP tool docs.
25. Added native collection lifecycle MCP tools: `linkwarden_create_collection`, `linkwarden_update_collection` (rename/move), and `linkwarden_delete_collection` with write-mode enforcement and audit logging.
26. Added native link organization tools: `linkwarden_set_links_collection` (bulk assign/remove collection) and `linkwarden_set_links_pinned` (bulk pin/unpin) with dry-run previews and apply execution.
27. Added `linkwarden_clean_link_urls` to remove tracking parameters (`utm_*` and common tracker keys) with dry-run preview and apply mode.
28. Extended Linkwarden client with native `get/update/deleteCollection`, `deleteLink`, and `setLinkPinned` support plus `/api/v1/users/me` resolution for relation-based pin writes.
29. Extended `linkwarden_update_link` payload support with `pinned` toggles and output field propagation.
30. Extended user settings model with per-user offline policy fields (`offlineDays`, `offlineMinConsecutiveFailures`, `offlineAction`, `offlineArchiveCollectionId`) and migration logic for existing SQLite instances.
31. Reworked `linkwarden_monitor_offline_links` and `linkwarden_run_daily_maintenance` to resolve policy from per-user settings and support both archive and delete actions natively.
32. Added new admin UI backend/API + dashboard controls to configure per-user 404/offline policy directly in `/admin` (`/admin/ui/admin/users/:userId/offline-policy`).
33. Added regression coverage for new tool schemas, write-mode gating on new mutating tools, URL cleaner behavior, and native client contracts for collection/link pin+delete operations.
34. Bumped package/server version to `0.1.6` (`package.json`, `package-lock.json`, `src/version.ts`) for the new native capability release.
35. Ran full post-change validation: `npm run lint` and `npm run build` locally, plus full `npm test` in isolated Docker (`node:20-alpine`) to bypass local optional Rollup binary issue; all tests pass (`50/50`).
36. Found and fixed native runtime contract mismatch where `linkwarden_create_collection` sent `parentId: null`; root collection creation now omits `parentId` entirely for Linkwarden compatibility.
37. Found and fixed native runtime contract mismatch where `linkwarden_update_link` writes missed required Linkwarden fields (`id`, `collection.ownerId`, full payload context); update path now composes payload from current link + optional overrides.
38. Found and fixed native tag-creation contract mismatch by switching `createTag` payload from `{name}` to native `{tags:[{label}]}` and adding regression coverage for this request shape.
39. Fixed OAuth refresh-token rotation safety by validating client/resource/scope before revoking refresh tokens, preventing accidental token loss on invalid refresh requests.
40. Added token-endpoint compatibility for refresh requests without `client_id` by deriving the effective client binding from the stored refresh token when omitted.
41. Hardened forwarded-header normalization (`x-forwarded-host`/`x-forwarded-proto` comma-chain handling) and added regression tests for both header normalization and refresh flow edge cases.
42. Bumped package/server version metadata to `0.1.7` (`package.json`, `package-lock.json`, `src/version.ts`) for the OAuth refresh stability fix release.
43. Built and pushed a Synology-compatible multi-arch Docker release to Docker Hub (`docker.io/wirrockendigital/linkwarden-mcp:0.1.7` and `:latest`) for `linux/amd64` and `linux/arm64`.
44. Verified published image manifests and digest (`sha256:1a922252d69e6c7d87b2f3b164a891983405b80e1daacec4da139009d306b10c`) for both tags.
45. Added deterministic local paging fallback for `listCollections` and `listTags` when upstream ignores `limit/offset`, including inferred totals for unpaged responses.
46. Added regression tests proving collection/tag paging returns the requested window even when Linkwarden returns full unpaged arrays.
47. Bumped package/server version metadata to `0.1.8` (`package.json`, `package-lock.json`, `src/version.ts`) for the paging-stability hotfix release.
48. Built and pushed a Synology-compatible multi-arch Docker release to Docker Hub (`docker.io/wirrockendigital/linkwarden-mcp:0.1.8` and `:latest`) for `linux/amd64` and `linux/arm64`.
49. Verified published image manifests and digest (`sha256:b27d81653bd31f5da6dbcbdd0ac500ff4aa7a94f51e58d4e1a081e9521641657`) for both tags.
50. Ran a full live MCP regression round against the connected Linkwarden and re-validated canonical inventory totals after cleanup: `1162` links, `389` collections, `3` tags, `2` pinned links.
51. Reproduced and fixed `linkwarden_clean_link_urls` global-failure behavior on mixed-access batches by isolating inaccessible link IDs instead of aborting the full operation.
52. Reproduced and fixed native tag-write failures (`Invalid input ... [tags, 0, name]`) by resolving and caching tag names and always sending Linkwarden-native tag objects as `{id, name}`.
53. Reworked offline-link health classification to treat `404`/`410` as down while still accepting protected endpoints (`401`/`403`) as reachable.
54. Added regression tests for (a) mixed-access URL-clean dry-run behavior and (b) 404 status classification in offline monitoring, plus stricter client tests for native tag payload requirements.
55. Bumped package/server version metadata to `0.1.9` (`package.json`, `package-lock.json`, `src/version.ts`) for the native clean/tag/offline bugfix release.
56. Built and pushed a Synology-compatible multi-arch Docker release to Docker Hub (`docker.io/wirrockendigital/linkwarden-mcp:0.1.9` and `:latest`) for `linux/amd64` and `linux/arm64`.
57. Verified published image manifest index digest `sha256:40270210d6edc20484fb0af6a2226eff4cf9aa34a13e78ff613af04773ffe780` with platform manifests for `linux/amd64` and `linux/arm64`.
58. Ran the full automated suite in isolated Docker (`node:20-alpine`) after bugfixes; all tests pass (`58/58`).
59. Ran release gate checks in isolated Docker (`npm run lint`, `npm run build`) with green results.
60. Fixed `linkwarden_monitor_offline_links` native paging by adding explicit `offset` support and applying the paging window as `offset` first, then optional `limit`.
61. Extended offline monitor responses with deterministic `paging` metadata (`offset`, `limit`, `totalMatched`) to make full-corpus scans auditable from MCP output.
62. Wired `offline.offset` through `linkwarden_run_daily_maintenance` and updated both tool schemas to accept/validate `offset` for native monitor execution.
63. Added regression tests for monitor offset handling and daily-maintenance offline offset forwarding, plus schema default assertions for `offset=0`.
64. Bumped package/server version metadata to `0.1.10` (`package.json`, `package-lock.json`, `src/version.ts`) for the native offline-monitor pagination fix release.
65. Built and pushed a Synology-compatible multi-arch Docker release to Docker Hub (`docker.io/wirrockendigital/linkwarden-mcp:0.1.10` and `:latest`) for `linux/amd64` and `linux/arm64`.
66. Verified published image manifest index digest `sha256:909dd217b669f21963598066328ef53f7defd0a47abb41edcb344223b8f8ebea` with platform manifests for `linux/amd64` and `linux/arm64`.

## 2026-02-17

1. Reproduced MCP live-test blocker where all Linkwarden MCP calls fail before handler execution with transport-level `Auth required`.
2. Hardened bearer parsing in `extractBearerToken` to accept whitespace variants (`Bearer    token`, tab-separated values, surrounding whitespace) and reject malformed tokens containing embedded whitespace.
3. Added canonical OAuth resource normalization in `src/utils/oauth.ts` (`normalizeResourceValue`) so host casing, trailing slashes, query strings, and fragments no longer break resource equality checks.
4. Fixed OAuth access-token validation in `SqliteStore.authenticateOAuthAccessToken` to use normalized resource matching instead of raw string equality.
5. Added regression coverage for the auth hardening in `test/auth.test.ts` (whitespace/tabs/malformed bearer header cases).
6. Added regression coverage for resource normalization in `test/oauth-resource.test.ts` and a store-level OAuth auth regression in `test/oauth-access-resource-match.test.ts`.
7. Documented environment blocker for full local validation: dependency install is currently blocked by sandbox DNS/network (`ENOTFOUND registry.npmjs.org`) and SMB lock artifacts in the workspace `node_modules` tree.
8. Bumped package/server version metadata to `0.2.8` (`package.json`, `package-lock.json`, `src/version.ts`) for the auth-hardening follow-up release.
9. Built and pushed a Synology-compatible multi-arch Docker release to Docker Hub (`docker.io/wirrockendigital/linkwarden-mcp:0.2.8` and `:latest`) for `linux/amd64` and `linux/arm64`.
10. Verified published manifest index digest `sha256:91bc7742876e06ec6ded02b05671080f24b5a479f361153caf5ff8c72da1938a` for both tags and platform manifests.
11. Extended `LinkSelector` and MCP selector schema for natural date and name-based filters: `createdAtFrom`, `createdAtTo`, `createdAtRelative`, `timeZone`, `tagNamesAny`, `tagNamesAll`, `collectionNamesAny`.
12. Added strict selector validation guards for date-mode conflicts and id/name axis conflicts (`tagIds*` vs `tagNames*`, `collectionId` vs `collectionNamesAny`).
13. Implemented timezone-aware created-at window compiler in `src/utils/created-window.ts` with deterministic inclusive bounds and relative modes (`rolling`, `previous_calendar`) plus fallback timezone chain.
14. Extended `resolveLinks` in MCP tools to resolve tag/collection names via exact + alias (tags) + strict fuzzy matching, emit warnings, and apply created-at filtering on `createdAt`.
15. Fixed descendant collection filtering in query resolution by avoiding overly narrow upstream collection pre-filters when descendant scopes are requested.
16. Extended `user_settings` with persisted per-user `query_timezone` (schema + migration + getters/setters) and wired `setUserTaggingPreferences` to update/reset that value.
17. Extended admin/user tagging preference APIs and dashboard controls to manage `queryTimeZone` directly in the existing tagging preference flows.
18. Added schema and utility test coverage for the new selector rules and created-at window compiler (`test/tool-schema-safety.test.ts`, `test/created-window.test.ts`) plus updated settings-related test fixtures.
19. Updated MCP tool documentation and README examples for natural date queries and name-based selector filters.
20. Local quality gates could not be executed in this sandbox because toolchain binaries are missing (`eslint`, `vitest`, `tsc` not found in environment).
21. Finalized release metadata for this feature set by bumping project/server version identifiers to `0.2.9`.
22. Bumped package/server version metadata to `0.2.10` (`package.json`, `package-lock.json`, `src/version.ts`) before Synology Docker release build/push.
23. Bumped package/server version metadata to `0.2.11` (`package.json`, `package-lock.json`, `src/version.ts`) before Synology Docker release build/push.
24. Extended `user_settings` schema/migration with native new-links routine fields (enabled, interval, module set, batch size, createdAt/id cursor, run state, and backfill request/confirmation flags).
25. Added typed store APIs for routine management in `SqliteStore`: read/write settings, cursor updates, run-state persistence, enabled-user listing for scheduler ticks, and backlog estimation helper.
26. Added new domain models in `src/types/domain.ts` for routine modules/settings/status (`NewLinksRoutineModule`, `NewLinksCursor`, `NewLinksRoutineSettings`, `NewLinksRoutineStatus`) and wired them into `UserSettings`.
27. Implemented native routine service `src/services/new-links-routine.ts` with strict `(createdAt,id)` cursor logic, deterministic sorting, fixed module order (`governed_tagging -> normalize_urls -> dedupe`), per-user maintenance lock, best-effort failure handling, and safe cursor advancement only across successful prefix items.
28. Added native MCP tools `linkwarden_get_new_links_routine_status` and `linkwarden_run_new_links_routine_now` including schema/registry/tool-discovery wiring and shared service execution path.
29. Added in-process scheduler loop in `src/server.ts` (1-minute tick, per-user due evaluation, shared routine service execution, shutdown-safe timer cleanup) without external cron dependency.
30. Extended user UI backend/API with native routine routes:
   - `GET /admin/ui/user/new-links-routine`
   - `POST /admin/ui/user/new-links-routine`
31. Extended dashboard UI with routine controls/status (enable, interval, batch size, module selection, backfill request/confirmation) and status rendering including warnings.
32. Added regression coverage for store-side routine behavior in `test/new-links-routine-store.test.ts` and extended tool schema safety coverage for the two new MCP tools.
33. Updated user docs in `README.md` and MCP tool docs in `docs/05-mcp-tools.md` for the new routine APIs and tool usage.
34. Executed quality gates after implementation:
   - `npm -C /Volumes/dev/linkwarden-mcp run lint` green
   - `npm -C /Volumes/dev/linkwarden-mcp run test` green (`69/69`)
   - `npm -C /Volumes/dev/linkwarden-mcp run build` green
35. Bumped project/server version metadata to `0.2.12` (`package.json`, `package-lock.json`, `src/version.ts`) for the new-links routine release build.
36. Built and pushed a Synology-compatible multi-arch Docker release to Docker Hub (`docker.io/wirrockendigital/linkwarden-mcp:0.2.12` and `:latest`) for `linux/amd64` and `linux/arm64`.
37. Verified published manifest index digest `sha256:f617db90d5c863b628213db30d411d9f51d297125d65bdb19c87be616c6ee4c4` for both tags with platform manifests present for `linux/amd64` and `linux/arm64`.
38. Added native governed-tagging inference provider support (`builtin`, `perplexity`, `mistral`, `huggingface`) in global tagging policy model and MCP server-info metadata.
39. Implemented strict provider integration for governed tagging context extraction with OpenAI-compatible chat endpoints, deterministic token parsing, explicit env-key checks, and no fallback path when an external provider is selected.
40. Extended admin tagging-policy UI/API to configure `inferenceProvider` and `inferenceModel`, including validation that `huggingface` requires an explicit model id.
41. Added provider utility regression tests (`test/tag-inference-provider.test.ts`) plus store-policy test updates for new default/custom inference fields.
42. Updated docs (`README.md`, `docs/05-mcp-tools.md`, `linkwarden-mcp.env.example`) with provider capabilities, required env vars, and Hugging Face arbitrary model configuration guidance.

## 2026-02-19

1. Bumped release metadata to `0.2.14` by updating `package.json`, `package-lock.json`, and `src/version.ts`.
2. Fixed Docker build context mismatch for release builds by removing non-existent `.prettierrc` from the Dockerfile copy step.
3. Built and pushed a Synology-compatible multi-arch Docker release to Docker Hub (`docker.io/wirrockendigital/linkwarden-mcp:0.2.14` and `:latest`) for `linux/amd64` and `linux/arm64`.
4. Verified published image manifest index digest `sha256:5bde5ccdf597bedc7a3989179f7a0df9d93a65297b419cf2973b6fe21b4bc703` and confirmed platform manifests for both `linux/amd64` and `linux/arm64`.

## 2026-02-20

1. Added per-user chat-control persistence for archive routing in SQLite (`user_chat_control`) with default `archive_collection_name = 'Archive'` and optional `archive_collection_parent_id`.
2. Added migration logic plus normalized store getters/setters for chat-control settings and seeded default rows during user creation.
3. Added UI/backend endpoints `GET/POST /admin/ui/user/chat-control` and dashboard controls for archive collection name and optional parent collection id.
4. Reworked soft-delete archive resolution to be backend-driven per user: exact name match, auto-create when missing, and deterministic multi-match choice (root first, then smallest id).
5. Updated `linkwarden_delete_links` and `linkwarden_merge_duplicates` soft-delete flows to use the new resolver and continue without hard failures when archive collections are missing in dry-run mode.
6. Extended audit/operation summaries for soft-delete flows with archive resolution details (`archiveCollectionId`, creation flag, and applied strategy).
7. Added regression tests for chat-control persistence defaults/custom values and a dedicated archive resolution suite covering create/single-match/multi-match/dry-run warning/upstream permission-error behavior.
8. Updated user-facing docs (`README.md`, `docs/03-setup-und-betrieb.md`) with per-user archive naming defaults, auto-create semantics, and parent/naming recommendations.
9. Local quality gates could not be executed in this sandbox after these changes because dependency installation is blocked by network DNS resolution (`ENOTFOUND registry.npmjs.org`), leaving `tsc`/`vitest` unavailable.
10. Added a Docker-based quality-gate runner (`tools/run-in-docker.sh`) plus npm scripts (`lint:docker`, `build:docker`, `test:docker`, `qa:docker`) as a stable fallback when host-side npm/toolchain resolution is unstable.
11. Updated `.github/workflows/release-docker.yml` to build and push multi-arch (`linux/amd64`, `linux/arm64`) images to GHCR and Docker Hub on every branch push (plus semver-tag pushes), including branch/sha tags and `latest` on the default branch.
12. Implemented a global `/admin` theme system (Login, First-Run, Unlock, Dashboard) with system-default dark mode, manual `system|light|dark` override via `localStorage["lwmcp.themePreference"]`, early head bootstrap to prevent FOUC, and shared contrast-focused CSS tokens using brand accent `#E94C16`.
13. Added a reusable theme switcher control to all `/admin` pages and verified behavior with full Docker quality gates (`npm run qa:docker`) passing (`lint`, `build`, `80/80` tests).
14. Refactored `/admin` dashboard IA to role-aware two-level tabs (`Übersicht`, `Mein Konto`, `Automationen`, `Integrationen`, `Governance`, `Administration`) with URL deep-link state via hash (`#tab=<top>&sub=<sub>`), tab fallback normalization, and sticky top navigation.
15. Added lazy per-panel loading with cache (`panelLoaders` + `loadedPanels`) and moved initial eager data loading to tab-activation flow while keeping existing endpoint/action compatibility.
16. Replaced the previous central action output workflow with toast notifications, inline field-error rendering for zod-style `fieldErrors`, panel dirty-state guard on tab changes, and an optional debug drawer for raw JSON response inspection.
17. Completed the Phase-2/3 admin IA delta in `src/http/ui.ts` by finalizing explicit tab-state utilities (`parseTabState`, `serializeTabState`, `applyTabState`, `isTabAllowedForRole`) and deterministic hash fallback handling.
18. Added role-aware A11y tab semantics end-to-end: ARIA tablist/tab/tabpanel wiring, deterministic panel ids, keyboard navigation (`ArrowLeft/ArrowRight/Home/End/Enter/Space`), and focus management after tab activation.
19. Implemented inflight request dedupe for UI API calls using `inflightRequests` keyed by `METHOD + URL + stable body hash`, including canonical JSON body normalization for semantically equal payloads.
20. Implemented panel-load dedupe with `inflightPanelLoads` plus stale-aware lazy reload so panels are loaded once, then only reloaded when explicitly invalidated.
21. Added deterministic mutation invalidation matrix (`mutationInvalidationMap`) with wildcard expansion (`administration:*`, `governance:*`) and active-panel immediate refresh while inactive stale panels reload on next open.
22. Unified feedback API behavior with `showToast(type, message, opts)`, `showFieldError(control, message)`, and `openDebugDrawer(payload, { autoOpenOnError })`, including automatic debug-drawer open on API errors.
23. Consolidated dense admin forms into clearer grouped sections (`Anlegen`, `Aktiv/Write-Mode`, `404-Policy`, `Global`, `Provider`, `Benutzerpräferenzen`) without breaking existing DOM ids or action function names.
24. Added overview KPI cards (`role`, `write-mode`, `token configured`, `routine status`, `last action`) sourced from existing `/admin/auth/me` and routine status calls without introducing new backend endpoints.
25. Re-ran full quality gates via Docker after the delta refactor: `npm run qa:docker` green (`eslint`, `tsc`, and `vitest` with `80/80` tests passing).
26. Finalized the delta rollout by correcting admin panel-to-tab mappings and removing duplicate `uebersicht:status` panel keys so ARIA `tabpanel` ids remain unique and deterministic.
27. Upgraded unsaved-change handling from panel-level to section-level by introducing `data-form-section` markers, `sectionRegistry`, and `dirtySections`, including section-aware guard dialogs that name affected form groups.
28. Added targeted dirty-clear behavior per mutation via `mutationSections` in `api(...)`, so successful saves clear only the touched section(s) instead of the full panel state.
29. Added explicit inline-script UI contracts with JSDoc typedefs (`TabKey`, `SubTabKey`, `TabDefinition`, `LoadState`, `RequestState`) and helper annotations for tab state and loader orchestration.
30. Finalized A11y polish by hardening dynamic `aria-labelledby` updates for visible panels, adding `aria-live=\"polite\"` to overview status feedback, and introducing configurable per-nav focus modes (`topNavFocusMode`, `subNavFocusMode`).
31. Added optional info-toasts for no-op tab activations and no-op panel invalidation paths, and persisted debug-drawer visibility in `sessionStorage` (`lwmcp.debugDrawerOpen`).
32. Added dedicated UI regression suite `test/admin-ui-refactor.test.ts` to lock deep-link/tab contracts, dedupe/invalidation orchestration, feedback helper usage, A11y keyboard hooks, section-guard markers, and stable legacy handler names.
33. Extended `README.md` with a concise `/admin` UX summary (role-aware tabs, hash deep-links, lazy-load+cache, toast/inline/debug feedback, theme persistence, keyboard navigation).
34. Revalidated the complete UI refactor gate with Docker quality checks after section-guard and contract-test additions: `npm run qa:docker` green with `20/20` test files and `86/86` tests passing.
35. Fixed native Linkwarden link creation payload in `src/linkwarden/client.ts` by resolving `tagIds` to object-based `tags` entries (`{id,name}`) before `POST /api/v1/links`, eliminating schema mismatches like `expected object, received number [tags, 0]`.
36. Added sanitized debug shape logging for link create payloads (`event: linkwarden_create_link_payload_shape`) to simplify runtime diagnosis without leaking secrets.
37. Hardened `linkwarden_capture_chat_links` apply path with a deterministic fallback: on tag-related link-create validation errors, retry once without tags, keep link creation successful, emit warning, and report `summary.createdWithoutTags`.
38. Added regression coverage for this bugfix:
   - `test/linkwarden-client.test.ts`: validates object-based `tags` payload for native link create requests.
   - `test/capture-chat-links.test.ts`: validates tag-failure fallback (`retry without tags`) with successful creation + warning + `createdWithoutTags`.
39. Revalidated full quality gates after the bugfix with Docker: `npm run qa:docker` green (`21/21` test files, `95/95` tests).
40. Fixed native link-create collection payload shape in `src/linkwarden/client.ts` to send `collection: { id }` (instead of relying on `collectionId`) so captured links are stored in the resolved chat collection instead of `Unorganized`.
41. Added explicit capture warning when `chatName` is omitted, so callers see that fallback `Current Chat` was used and can pass the intended chat title.
42. Extended regression coverage:
   - `test/linkwarden-client.test.ts`: createLink contract now asserts relation payload contains `"collection":{"id":...}` and no top-level `collectionId`.
   - `test/capture-chat-links.test.ts`: verifies fallback warning when `chatName` is not provided.
43. Revalidated complete QA gate after collection + chatName-warning fixes: `npm run qa:docker` green with `21/21` test files and `96/96` tests passing.
44. Added chat-title alias support in `linkwarden_capture_chat_links` (`chatTitle`, `conversationTitle`, `threadTitle`) and resolution priority so clients can pass the current chat title without relying on manual user prompting.
45. Hardened hierarchy reuse by making collection-name matching case-insensitive (with whitespace normalization) in parent-scoped resolution to reduce duplicate auto-creation when only casing differs.
46. Added regression tests for alias-driven chat-name resolution and case-insensitive hierarchy reuse, plus schema-safety coverage for `conversationTitle`.
47. Revalidated full quality gates after chat-title alias + case-insensitive hierarchy fixes: `npm run qa:docker` green with `21/21` test files and `98/98` tests passing.
48. Added collection-pagination recovery in `listAllCollections`: when paged responses repeat, one unpaged fallback request merges missing collection ids to avoid false "missing collection" decisions.
49. Added client regression test for repeated-page pagination recovery so hierarchy resolution remains stable even with upstream offset bugs (`test/linkwarden-client.test.ts`).
50. Revalidated full QA after pagination recovery changes: `npm run qa:docker` green with `21/21` test files and `99/99` tests passing.
51. Extended user chat-control persistence with `ai_activity_retention_days` (`30|90|180|365`, default `180`) including schema migration, normalization, and API wiring via `GET/POST /admin/ui/user/chat-control`.
52. Implemented native AI activity log storage in SQLite via new table `ai_change_log` (with indexed filters for user/time/link/action/operation/undo status) and store methods for append/list/facets/undo-candidate/status/prune flows.
53. Added deterministic AI change-log derivation from MCP write operations in `src/mcp/tools.ts` and wired capture/mutate/delete/assign/governed-tagging/normalize/merge flows to append structured log entries.
54. Added selective undo engine `undoChangesByIds(...)` with write-mode enforcement, per-link newer-change conflict detection, status tracking (`applied|conflict|failed`), and audit logging.
55. Extended operation undo integration so `linkwarden_undo_operation` updates `ai_change_log` undo status for affected operation items.
56. Added user UI API endpoints for AI log and settings:
    - `GET /admin/ui/user/ai-log`
    - `GET /admin/ui/user/ai-log/facets`
    - `POST /admin/ui/user/ai-log/undo`
    - `GET /admin/ui/user/ai-log/settings`
    - `POST /admin/ui/user/ai-log/settings`
57. Added `/admin` dashboard sub-tab `Übersicht -> AI-Log` with filter bar, paging, bulk selection, change/operation undo actions, retention control, and debug/feedback integration.
58. Added regression coverage for AI-log store and UI integration (`test/ai-log-store.test.ts`, `test/admin-ui-refactor.test.ts`, updated capture/chat-control tests) and revalidated full quality gates: `npm run qa:docker` green with `22/22` test files and `103/103` tests passing.
59. Fixed a dashboard script regression in `src/http/ui.ts` by replacing nested backtick template literals inside the embedded `<script>` with string concatenation, restoring clean TypeScript compilation and runtime rendering for AI-log table/selection/paging/confirm flows.
60. Added throttled per-user AI-log pruning on read paths (`AI_LOG_PRUNE_THROTTLE_MS` + `pruneAiLogIfDue`) to keep retention cleanup opportunistic without triggering cleanup queries on every request.
61. Finalized release metadata to `0.2.22` (`package.json`, `package-lock.json`, `src/version.ts`) after revalidating full Docker quality gates (`npm run qa:docker` green).
62. Added native global OAuth refresh session lifetime support in encrypted runtime config via `oauthSessionLifetime` with presets `'permanent' | 1 | 7 | 30 | 180 | 365` and default `permanent`.
63. Updated setup/config crypto flow so legacy `config.enc` payloads without `oauthSessionLifetime` deterministically migrate to `permanent` on decrypt.
64. Switched OAuth token issuance to runtime-configured refresh session lifetime (`permanent` maps to `9999-12-31T23:59:59.000Z`) and removed refresh-TTL dependency on environment variables.
65. Added store method `rebaseActiveOAuthRefreshExpiries(...)` to immediately reapply new session lifetime presets to active non-revoked refresh tokens.
66. Added admin UI API endpoints for OAuth session settings:
    - `GET /admin/ui/admin/oauth-session`
    - `POST /admin/ui/admin/oauth-session` (persists config + returns `affectedCount` from immediate rebase).
67. Extended admin dashboard `Integrationen -> Linkwarden Ziel` with OAuth session lifetime controls (`Dauerhaft`, `Täglich`, `Wöchentlich`, `30`, `180`, `365`) including save feedback and live status text.
68. Updated deployment/user docs to reflect new runtime behavior and removed refresh-TTL env guidance (`README.md`, `docs/02-installation-portainer.md`, `docs/03-setup-und-betrieb.md`, `linkwarden-mcp.env.example`, `linkwarden-mcp.yaml`).
69. Added regression coverage for config migration and OAuth/session behavior (`test/crypto.test.ts`, `test/oauth-token-refresh.test.ts`, `test/oauth-session-lifetime-store.test.ts`).

## 2026-02-21

1. Added ConfigStore regression coverage for setup defaults/persistence of `oauthSessionLifetime` (`test/config-store-oauth-session.test.ts`) to lock the `permanent` default behavior.
2. Revalidated full Docker QA gate after OAuth session lifetime implementation: `npm run qa:docker` green with `24/24` test files and `110/110` tests passing.
3. Finalized release metadata to `0.2.23` (`package.json`, `package-lock.json`, `src/version.ts`) for commit/tag/push.
4. Added native per-user 404-monitor persistence fields in `user_settings` (`link_404_monitor_enabled`, `link_404_monitor_interval`, `link_404_to_delete_after`, run-state columns) with migration/default normalization to period-based presets (`monthly` / `after_1_year`).
5. Extended domain/store contracts with explicit 404-monitor types and APIs (`Link404MonitorInterval`, `Link404ToDeleteAfter`, `Link404MonitorSettings`, `Link404MonitorStatus`) plus new store methods for settings, run-state, and scheduler candidate listing.
6. Implemented new native routine service `src/services/link-404-routine.ts` with strict HTTP-404 detection, calendar-based escalation (`after_1_month|after_6_months|after_1_year`), automatic recovery untagging (`404` + `to-delete` removal), maintenance locking, and operation/AI-log audit integration.
7. Wired 404-monitor scheduler execution into `src/server.ts` as a dedicated background path parallel to the new-links scheduler, including structured tick/user completion/failure logging.
8. Added MCP tool surface for 404 monitoring:
   - `linkwarden_get_link_404_monitor_status`
   - `linkwarden_run_link_404_monitor_now`
   including schema registry and tool discovery updates.
9. Extended `/admin` user backend/API + dashboard with new automation panel `404-Monitor`:
   - `GET /admin/ui/user/link-404-monitor`
   - `POST /admin/ui/user/link-404-monitor`
   and UI controls for enable toggle, interval presets (`daily|weekly|biweekly|monthly|semiannual|yearly`), and escalation presets (`after_1_month|after_6_months|after_1_year`).
10. Added regression coverage for new behavior:
    - store defaults/persistence/run-state (`test/link-404-monitor-store.test.ts`)
    - schedule semantics (`test/link-404-routine-schedule.test.ts`)
    - runtime tag/update/recovery/error paths (`test/link-404-routine.test.ts`)
    - tool schema/discovery and admin UI contract updates (`test/tool-schema-safety.test.ts`, `test/admin-ui-refactor.test.ts`).
11. Finalized release metadata to `0.2.24` (`package.json`, `package-lock.json`, `src/version.ts`) for commit/tag/push.
