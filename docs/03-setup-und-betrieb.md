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
- `linkwardenApiToken`
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
4. Write-Mode pro Benutzer steuern

### User-Flow

1. Login auf `GET /`
2. Eigenen Write-Mode toggeln
3. Eigene API-Keys verwalten

## Health und Readiness

- `GET /health` -> Prozess lebt
- `GET /ready` -> Setup/Unlock/User/Whitelist/Target/Upstream sind geprüft

