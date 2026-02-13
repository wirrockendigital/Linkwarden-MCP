# 07 - Troubleshooting

## `401 unauthorized` auf `/mcp`

Ursachen:

- falscher Bearer-Token im Connector
- API-Key revoked
- Benutzer deaktiviert

Lösung:

- im Admin-UI neuen API-Key ausstellen
- Connector-Token in ChatGPT aktualisieren

## `403 write_mode_disabled`

Ursache:

- Benutzer versucht Write-Tool ohne aktivierten eigenen Write-Mode

Lösung:

- im User-UI oder Admin-UI den Write-Mode für diesen Benutzer aktivieren

## `403 base_url_not_whitelisted`

Ursache:

- aktive Linkwarden-Base-URL passt nicht zur Whitelist

Lösung:

- Whitelist im Admin-UI ergänzen/anpassen
- anschließend Base-URL erneut prüfen

## `503 config_locked`

Ursache:

- Auto-Unlock fehlgeschlagen (z. B. Passphrase-Datei fehlt/falsch)

Lösung:

1. Passphrase-Datei prüfen (`MCP_MASTER_PASSPHRASE_HOST_FILE`)
2. Fallback-Entsperrung:

```bash
curl -X POST http://192.168.123.220:8080/setup/unlock \
  -H 'content-type: application/json' \
  -d '{"passphrase":"<dein-master-passphrase>"}'
```

## `ready.ok = false`

Typische Ursachen:

- Setup nicht abgeschlossen
- kein User vorhanden
- Linkwarden Target fehlt
- Whitelist leer
- Linkwarden nicht erreichbar

Prüfen:

- `GET /ready`
- Netzwerkroute zu Linkwarden
- Linkwarden Token und Base-URL

## Debug-Logs aktivieren und auslesen

Empfehlung:

- in `linkwarden-mcp.env` auf `MCP_LOG_LEVEL=debug` setzen
- Stack neu deployen

Logs lesen:

```bash
docker logs -f linkwarden-mcp
```

Typische Event-Namen in den JSON-Logs:

- `http_request_start`, `http_request_complete`, `http_request_failed`
- `ui_login_attempt`, `ui_login_success`, `csrf_validation_failed`
- `mcp_auth_success`, `mcp_rpc_request_received`, `mcp_tool_execution_started`
- `linkwarden_request_started`, `linkwarden_request_retry_scheduled`, `linkwarden_request_completed`
