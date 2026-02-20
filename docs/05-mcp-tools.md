# MCP Tools (Alpha 0.2.x)

## Verfügbare Tools

- `linkwarden_get_server_info`
- `linkwarden_get_stats`
- `linkwarden_query_links`
- `linkwarden_aggregate_links`
- `linkwarden_get_link`
- `linkwarden_mutate_links`
- `linkwarden_delete_links`
- `linkwarden_list_collections`
- `linkwarden_create_collection`
- `linkwarden_update_collection`
- `linkwarden_delete_collection`
- `linkwarden_list_tags`
- `linkwarden_create_tag`
- `linkwarden_delete_tag`
- `linkwarden_assign_tags`
- `linkwarden_governed_tag_links`
- `linkwarden_normalize_urls`
- `linkwarden_find_duplicates`
- `linkwarden_merge_duplicates`
- `linkwarden_create_rule`
- `linkwarden_test_rule`
- `linkwarden_apply_rule`
- `linkwarden_run_rules_now`
- `linkwarden_capture_chat_links`
- `linkwarden_get_new_links_routine_status`
- `linkwarden_run_new_links_routine_now`
- `linkwarden_list_rules`
- `linkwarden_delete_rule`
- `linkwarden_create_saved_query`
- `linkwarden_list_saved_queries`
- `linkwarden_run_saved_query`
- `linkwarden_get_audit`
- `linkwarden_undo_operation`

## Standardisierte Responses

Alle Tool-Responses nutzen dasselbe Envelope:

- `ok`
- `data`
- `summary`
- `paging`
- `warnings`
- `error`
- `failures`

## Beispiele

Server-Version:

```text
Nutze linkwarden_get_server_info
```

Harte Zähler:

```text
Nutze linkwarden_get_stats
```

Deterministische Query mit Cursor:

```text
Nutze linkwarden_query_links mit selector {query:"security", includeDescendants:true} limit 50 fields ["id","title","url"] verbosity "minimal"
```

Natürliche Datumsfilter (angelegt-Zeit via `createdAt`):

```text
Nutze linkwarden_query_links mit selector {createdAtRelative:{amount:1,unit:"month",mode:"previous_calendar"}, timeZone:"Europe/Berlin"} limit 200
```

Absolute Datumsrange:

```text
Nutze linkwarden_query_links mit selector {createdAtFrom:"2026-01-01", createdAtTo:"2026-01-31", timeZone:"Europe/Berlin"} limit 200
```

Tag-Namen + Alias/Fuzzy + Datumsfilter:

```text
Nutze linkwarden_query_links mit selector {tagNamesAny:["Wohnmobil","WoMo"], createdAtRelative:{amount:1,unit:"month",mode:"previous_calendar"}} limit 200
```

Collection-Namen + Datumsfilter:

```text
Nutze linkwarden_query_links mit selector {collectionNamesAny:["Wohnmobil"], includeDescendants:true, createdAtRelative:{amount:1,unit:"month",mode:"previous_calendar"}} limit 200
```

Hinweise:

- `createdAtRelative` kann nicht mit `createdAtFrom/createdAtTo` kombiniert werden.
- Für Tag/Collection-Achsen gilt jeweils Name- oder ID-Filter, nicht beides gleichzeitig.
- Nicht auflösbare Namen und fuzzy-Auflösungen stehen im Response-Feld `warnings`.

Bulk-Mutation (Dry-Run):

```text
Nutze linkwarden_mutate_links mit selector {collectionId:123, includeDescendants:true} updates {tagMode:"add", tagNames:["security"]} dryRun true
```

Soft-Delete:

```text
Nutze linkwarden_delete_links mit selector {tagIdsAny:[9]} mode "soft" dryRun false
```

URL-Normalisierung:

```text
Nutze linkwarden_normalize_urls mit selector {query:"utm_"} dryRun true
```

Governed Tagging (One-Call):

```text
Nutze linkwarden_governed_tag_links mit selector {collectionId:123, includeDescendants:true} dryRun true
```

Hinweis zu AI-Providern für Governed Tagging:

- Provider-Auswahl erfolgt global über die Admin-Tagging-Policy (`inferenceProvider`).
- Unterstützt werden `builtin`, `perplexity`, `mistral`, `huggingface`.
- Für `huggingface` kann ein beliebiges gehostetes Modell über `inferenceModel` gesetzt werden.
- Für externe Provider müssen die passenden Env-Keys gesetzt sein:
  - `MCP_PERPLEXITY_API_KEY`
  - `MCP_MISTRAL_API_KEY`
  - `MCP_HUGGINGFACE_API_KEY`

Regel testen:

```text
Nutze linkwarden_test_rule mit id "rule-id"
```

AI-Chat-Links erfassen und dedupliziert speichern:

```text
Nutze linkwarden_capture_chat_links mit chatText "<chat transcript>" aiName "ChatGPT" chatName "Meeting 2026-02-20" dryRun false
```

Hinweis:

- Ziel ist immer `AI Chats > <AI Name> > <Chat Name>`.
- Wenn `chatName` nicht übergeben wird, nutzt das Tool den Fallback `Current Chat` und gibt dafür einen Warning-Hinweis zurück.
- Tagging wird über User-Chat-Control gesteuert (`AI Chat`-Tag und optionaler `AI Name`-Tag separat schaltbar).
- Falls Link-Erstellung mit Tags durch ein Upstream-Tag-Validation-Problem fehlschlägt, wird einmal ohne Tags erneut versucht und als Warning + `summary.createdWithoutTags` ausgewiesen.

New-Links-Routine Status:

```text
Nutze linkwarden_get_new_links_routine_status
```

New-Links-Routine sofort ausführen:

```text
Nutze linkwarden_run_new_links_routine_now
```

Gespeicherte Query ausführen:

```text
Nutze linkwarden_run_saved_query mit id "saved-query-id" limit 100
```

Undo:

```text
Nutze linkwarden_undo_operation mit operationId "operation-id"
```
