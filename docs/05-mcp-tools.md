# MCP Tools

## Verfügbare Tools

- `linkwarden_search_links`
- `linkwarden_get_server_info`
- `linkwarden_list_collections`
- `linkwarden_create_collection`
- `linkwarden_update_collection`
- `linkwarden_delete_collection`
- `linkwarden_list_tags`
- `linkwarden_create_tag`
- `linkwarden_delete_tag`
- `linkwarden_assign_tags`
- `linkwarden_get_link`
- `linkwarden_plan_reorg`
- `linkwarden_apply_plan`
- `linkwarden_update_link`
- `linkwarden_set_links_collection`
- `linkwarden_set_links_pinned`
- `linkwarden_bulk_update_links`
- `linkwarden_clean_link_urls`
- `linkwarden_monitor_offline_links`
- `linkwarden_run_daily_maintenance`
- `linkwarden_suggest_taxonomy` (optional)

## Safety by Design

- Listen/Suche sind paginiert und limitiert
- Schreibvorgänge benötigen aktivierten **benutzerspezifischen** Write-Mode
- Jeder Benutzer benötigt einen eigenen `Linkwarden API Key -> MCP`
- Reorganisation ist immer zweistufig:
  1. `linkwarden_plan_reorg` (Dry-run)
  2. `linkwarden_apply_plan` mit `confirm="APPLY"`

## Beispiele

Suche:

```text
Nutze linkwarden_search_links mit query "mail security" limit 20
```

Server-Version abfragen:

```text
Nutze linkwarden_get_server_info
```

Plan erzeugen:

```text
Erstelle mit linkwarden_plan_reorg eine tag-by-keywords Planung für "spf dkim dmarc mta-sts dane" und zeige Preview
```

Plan anwenden:

```text
Wende plan_id XYZ mit linkwarden_apply_plan confirm APPLY an
```

Tag erstellen:

```text
Nutze linkwarden_create_tag mit name "Security"
```

Tags per Name zuweisen (inkl. Auto-Create fehlender Tags):

```text
Nutze linkwarden_assign_tags mit linkIds [123,456] tagNames ["Security","DNS"] mode "add" createMissingTags true
```

Collection erstellen:

```text
Nutze linkwarden_create_collection mit name "Service" parentId null
```

Links Collection zuweisen/entfernen:

```text
Nutze linkwarden_set_links_collection mit linkIds [1,2,3] collectionId 77 dryRun true
Nutze linkwarden_set_links_collection mit linkIds [1,2,3] collectionId null dryRun false
```

Links pinnen/entpinnen:

```text
Nutze linkwarden_set_links_pinned mit linkIds [1,2,3] pinned true dryRun true
```

Tracking-Parameter entfernen:

```text
Nutze linkwarden_clean_link_urls mit linkIds [1,2,3] dryRun true removeUtm true removeKnownTracking true
```
