# MCP Tools

## Verfügbare Tools

- `linkwarden_search_links`
- `linkwarden_list_collections`
- `linkwarden_list_tags`
- `linkwarden_get_link`
- `linkwarden_plan_reorg`
- `linkwarden_apply_plan`
- `linkwarden_update_link`
- `linkwarden_bulk_update_links`
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

Plan erzeugen:

```text
Erstelle mit linkwarden_plan_reorg eine tag-by-keywords Planung für "spf dkim dmarc mta-sts dane" und zeige Preview
```

Plan anwenden:

```text
Wende plan_id XYZ mit linkwarden_apply_plan confirm APPLY an
```
