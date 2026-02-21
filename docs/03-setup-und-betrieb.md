# 03 - Setup und Betrieb

## First-Run im Browser

Nach dem Deploy öffnest du:

- `http://192.168.123.220:8080/`

Wenn der Server noch nicht initialisiert ist, erscheint dort direkt die Setup-Maske.

Du konfigurierst:

- `masterPassphrase`
- `adminUsername`
- `adminPassword`
- `linkwardenBaseUrl`
- `Linkwarden API Key -> MCP`
- optional `OAuth Client ID` + `OAuth Client Secret` (für statischen Connector-Client)
- Whitelist-Einträge (`domain`, `ip`, `cidr`)

## Wo wird die `masterPassphrase` konfiguriert?

Die `masterPassphrase` wird genau hier gesetzt:

- im First-Run Formular auf `GET /`
- technisch per `POST /setup/initialize`

Danach wird sie **nicht** als Klartext in der Datenbank gespeichert.
Sie dient zum Verschlüsseln/Entschlüsseln von `/data/config.enc`.

## Auto-Unlock nach Neustart

Wenn die Passphrase-Datei gemountet ist, startet der Container nach Neustart automatisch entsperrt.

Relevante Env-Werte:

- `MCP_MASTER_PASSPHRASE_HOST_FILE=/volume2/docker/linkwarden-mcp/master.passphrase`
- `MCP_MASTER_PASSPHRASE_FILE=/run/secrets/linkwarden-mcp-master-passphrase`

Die Host-Datei enthält genau die beim Setup gewählte `masterPassphrase` (eine Zeile).

## Manueller Unlock (Fallback)

Nur falls Auto-Unlock fehlschlägt:

```bash
curl -X POST http://192.168.123.220:8080/setup/unlock \
  -H 'content-type: application/json' \
  -d '{"passphrase":"<dein-master-passphrase>"}'
```

## Laufender Betrieb über UI

### Admin-Flow

1. Login auf `GET /`
2. Benutzer und API-Keys verwalten
3. Linkwarden Target + Whitelist pflegen
4. Linkwarden API Key -> MCP pro Benutzer setzen/rotieren
5. Write-Mode pro Benutzer steuern
6. OAuth Session-Laufzeit setzen (`Dauerhaft`, `Täglich`, `Wöchentlich`, `30`, `180`, `365` Tage)

### OAuth Session-Laufzeit (global)

Im Admin-Dashboard unter `Integrationen -> Linkwarden Ziel` steuert der Admin die Laufzeit von OAuth-Refresh-Sessions.

- Standard: `Dauerhaft`
- Änderung wirkt sofort auf aktive Refresh-Tokens
- Access-Token bleiben kurzlebig

### User-Flow

1. Login auf `GET /`
2. Eigenen Write-Mode toggeln
3. Eigenen Linkwarden API Key -> MCP setzen
4. Eigene MCP API-Keys verwalten

## Archiv-Collection pro User (Chat-Control)

Jeder User kann im Dashboard unter „Mein Chat-Control“ seine Archiv-Collection steuern:

- `Archiv-Collection-Name` (Default: `Archive`)
- optional `Archiv Parent Collection ID`
- `Chat-Link-Tag-Name` (Default: `AI Chat`)
- `AI Chat-Tag setzen` (Default: aktiv)
- `AI Name-Tag setzen` (Default: aktiv)

Empfehlung für den Betrieb:

- Nutze eine konsistente Namenskonvention, z. B. `Archive` für Standard-Archive oder `Archive Team` je Team.
- Setze `Archiv Parent Collection ID`, wenn Archiv-Collections gezielt unter einer festen Ober-Collection angelegt werden sollen.

Verhalten bei Soft-Delete (`ARCHIVE_TAG`):

- Existiert keine passende Collection mit exakt diesem Namen, legt das Backend sie automatisch an.
- Bei mehreren Treffern wird deterministisch gewählt:
  - zuerst Root-Collection (`parentId = null`)
  - bei mehreren Root-Treffern die kleinste `id`
  - ohne Root-Treffer insgesamt die kleinste `id`
- Das Tag `to-delete` wird bei Apply bei Bedarf automatisch angelegt und gesetzt.

Verhalten bei `linkwarden_capture_chat_links`:

- Ziel-Hierarchie: `AI Chats -> <AI Name> -> <Chat Name>`.
- Fehlende Collections werden bei Apply automatisch angelegt.
- Dedupe läuft innerhalb der Ziel-Collection (kanonische URL, keine Doppelanlagen).
- Tagging pro User:
  - statischer Tag aus `Chat-Link-Tag-Name` (wenn `AI Chat-Tag setzen` aktiv)
  - dynamischer Tag aus `AI Name` (wenn `AI Name-Tag setzen` aktiv)

## 404-Monitor im User-Backend

Im Tab `Automationen -> 404-Monitor` steuerst du die dauerhafte 404-Überwachung deiner Links pro User.

Einstellungen:

- `404-Monitor aktiviert`
- `Prüfintervall`: `täglich | wöchentlich | alle zwei Wochen | monatlich | halbjährlich | jährlich`
- `to-delete nach`: `nach einem Monat | nach einem halben Jahr | nach einem Jahr`

Defaults:

- Prüfintervall: `monatlich`
- `to-delete`-Eskalation: `nach einem Jahr`

Laufzeitverhalten:

- Es werden nur nicht archivierte Links geprüft.
- Nur HTTP `404` zählt als Offline-Fall.
- Bei `404` wird Tag `404` gesetzt.
- Bleibt der Link über den konfigurierten Zeitraum auf `404`, wird zusätzlich Tag `to-delete` gesetzt.
- Wird der Link wieder erreichbar (`status != 404`), entfernt der Monitor die Tags `404` und `to-delete` automatisch.

## AI-Aktivitätslog im User-Backend

Im Tab `Übersicht -> AI-Log` siehst du alle MCP/AI-Write-Änderungen deiner Links mit Zeitstempel.

Enthaltene Änderungsdaten:

- Aktionstyp (z. B. `create_link`, `normalize_url`, `tag_add`, `move_collection`)
- Link-Metadaten (`linkId`, Titel)
- Collection-Änderung (`von -> nach`)
- Tag-Deltas (`+/-`)
- URL-Vorher/Nachher inkl. Markierung für Tracking-Kürzung
- Undo-Status (`pending`, `applied`, `conflict`, `failed`)

Filtermöglichkeiten:

- Volltext (`URL`, Titel, Collection, Tag)
- Datumsbereich (`von/bis`)
- Aktionstyp und Tool
- Link-ID
- Collection von / nach
- Tag enthält
- Tracking gekürzt (ja/nein)
- Undo-Status

Undo-Modi im Log:

- Ausgewählte Änderungen rückgängig machen
- Ausgewählte Operationen rückgängig machen

Hinweise:

- Undo ist nur mit aktivem Write-Mode erlaubt.
- Bei Konflikten (neuere offene Änderung auf demselben Link) wird der betroffene Eintrag als `conflict` markiert und nicht still überschrieben.

Retention pro User:

- Einstellbar auf `30`, `90`, `180`, `365` Tage
- Default ist `180` Tage
- Alte Logeinträge werden nutzerbezogen beim Zugriff/Schreiben opportunistisch bereinigt

## Health und Readiness

- `GET /health` -> Prozess lebt
- `GET /ready` -> Setup/Unlock/User/Whitelist/Target/Upstream sind geprüft
