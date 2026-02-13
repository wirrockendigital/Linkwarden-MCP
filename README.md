# linkwarden-mcp

`linkwarden-mcp` ist ein eigenständiger MCP-Server als Docker-Container für deine Synology/Portainer-Umgebung.
Er verbindet ChatGPT (Developer Mode / Custom MCP Connector) mit deiner selbstgehosteten Linkwarden-Instanz.

## Was der Container macht

- Stellt einen **Remote MCP Server** via **Streamable HTTP** unter `POST /mcp` bereit
- Nutzt intern die Linkwarden REST API (`/api/v1/...`)
- Hat eine browserbasierte Admin/User-Oberfläche unter `GET /`
- Unterstützt Multi-User mit Rollen `admin` und `user`
- Erzwingt pro Benutzer einen eigenen `write_mode_enabled` für Schreiboperationen
- Erzwingt Dry-run/Apply-Sicherheit für Reorg-Pläne (`confirm="APPLY"`)
- Schreibt Audit-Logs für Write-Operationen

## Verzeichnis und Dateinamen

Projektpfad:

- `/Volumes/dev/linkwarden-mcp`

Portainer-Dateien (Projektname als Präfix):

- `/Volumes/dev/linkwarden-mcp/linkwarden-mcp.yaml`
- `/Volumes/dev/linkwarden-mcp/linkwarden-mcp.env`
- `/Volumes/dev/linkwarden-mcp/linkwarden-mcp.env.example`

## Voraussetzungen

- Synology NAS mit Docker + Portainer
- Docker-Netzwerk `allmydocker-net` existiert
- Feste IP `192.168.123.220` ist im Netz verfügbar
- Linkwarden ist intern aus dem Netzwerk erreichbar (z. B. `http://linkwarden:3000`)
- DSM Reverse Proxy terminiert TLS und routet intern auf `http://192.168.123.220:8080`

## Deployment mit Portainer

1. In Portainer `Stacks` -> `Add stack` öffnen
2. Inhalt von `/Volumes/dev/linkwarden-mcp/linkwarden-mcp.yaml` einfügen
3. Unter `Environment variables` die Datei `/Volumes/dev/linkwarden-mcp/linkwarden-mcp.env` hochladen
4. Stack deployen

Hinweis:

- Der Stack hat optionalen Host-Portzugriff über einen unüblichen Port `39227`.
- Standardmäßig ist der Port nur lokal am NAS gebunden (`MCP_HOST_BIND_IP=127.0.0.1`).
- Für direkten Zugriff im LAN setze `MCP_HOST_BIND_IP` auf deine NAS-IP oder `0.0.0.0`.
- Zugriff intern über Container-IP bleibt `192.168.123.220:8080`; extern bevorzugt weiterhin über DSM Reverse Proxy.
- Der Container läuft als konfigurierbarer User über `MCP_RUN_UID`/`MCP_RUN_GID`.

Wichtige Env-Werte in `linkwarden-mcp.env`:

- `MCP_DOCKER_NETWORK=allmydocker-net`
- `MCP_STATIC_IP=192.168.123.220`
- `MCP_RUN_UID=1061`
- `MCP_RUN_GID=1061`
- `MCP_VOLUME_HOST=/volume2/docker/linkwarden-mcp/data`
- `MCP_MASTER_PASSPHRASE_HOST_FILE=/volume2/docker/linkwarden-mcp/master.passphrase`
- `MCP_MASTER_PASSPHRASE_FILE=/run/secrets/linkwarden-mcp-master-passphrase`
- `MCP_LOG_LEVEL=debug`
- `MCP_SESSION_TTL_HOURS=12`
- `MCP_COOKIE_SECURE=auto`
- `MCP_HOST_BIND_IP=127.0.0.1`
- `MCP_HOST_PORT=39227`

Optionaler Direktzugriff per NAS-IP:

- Beispiel: `MCP_HOST_BIND_IP=192.168.123.50`
- dann ist die UI/MCP direkt über `http://192.168.123.50:39227` erreichbar

Hinweis zu Logs:

- `MCP_LOG_LEVEL=debug` loggt alle Debug-Events (empfohlen für Fehlersuche)
- für ruhigeren Betrieb kannst du auf `info` zurückstellen

## First-Run Setup im Browser

Nach dem ersten Start:

1. Öffne `http://192.168.123.220:8080/`
2. Fülle den First-Run Setup-Dialog aus:
   - `masterPassphrase`
   - `adminUsername`
   - `adminPassword`
   - `linkwardenBaseUrl`
   - `linkwardenApiToken`
   - `whitelistEntries` (Pflicht, kein Allow-All)
3. Optional kannst du direkt einen initialen Admin-MCP-Key generieren lassen
4. Danach login mit Admin-Zugang im selben UI

Whitelist-Format im UI:

- `domain:linkwarden.internal`
- `ip:192.168.123.10`
- `cidr:192.168.123.0/24`

Nicht erlaubt:

- Wildcards (`*.example.com`)
- `0.0.0.0/0`, `::/0`

## Annahmen

- Linkwarden API ist unter `/api/v1/...` erreichbar und nutzt Bearer Token.
- Synology DSM Reverse Proxy terminiert TLS für den externen Zugriff.
- Der MCP-Container erreicht Linkwarden intern über das Docker-Netzwerk.

## Auto-Unlock nach Neustart

Damit der Container nach Neustart ohne manuelles Unlock direkt läuft:

1. Lege auf dem Host die Datei aus `MCP_MASTER_PASSPHRASE_HOST_FILE` an
2. Schreibe die beim Setup gewählte `masterPassphrase` als eine Zeile hinein
3. Datei nur lokal und mit restriktiven Rechten halten
4. Der Container liest diese Datei beim Start und entsperrt `config.enc` automatisch

Fallback (nur wenn Auto-Unlock fehlschlägt):

```bash
curl -X POST http://192.168.123.220:8080/setup/unlock \
  -H 'content-type: application/json' \
  -d '{"passphrase":"<dein-master-passphrase>"}'
```

## Admin- und User-Oberfläche (`GET /`)

### Admin kann

- Benutzer anlegen/deaktivieren
- Rollen vergeben (`admin`/`user`)
- API-Keys ausstellen/revoken
- Write-Mode pro Benutzer setzen
- Linkwarden-Ziel und Whitelist pflegen
- Linkwarden API-Token rotieren

### User kann

- Eigene Daten sehen
- Eigenen Write-Mode ein/ausschalten
- Eigene API-Keys erstellen/revoken

Keine Selbstregistrierung vorhanden.

## ChatGPT Developer Mode: Custom MCP Connector

1. In ChatGPT (Workspace Admin) Developer Mode für MCP Connectoren aktivieren
2. Custom Connector anlegen:
   - Name: `linkwarden-mcp`
   - Server URL: `https://<deine-domain>/mcp`
   - Auth: Bearer Token
   - Token: pro Benutzer eigener MCP-API-Key aus Admin-UI
3. Tool Discovery testen (`tools/list`)

Beispielprompts:

- `Nutze linkwarden_search_links mit query "mail security" limit 20`
- `Erstelle mit linkwarden_plan_reorg eine tag-by-keywords Planung für "spf dkim dmarc mta-sts dane" und zeige Preview`
- `Wende plan_id XYZ mit linkwarden_apply_plan confirm APPLY an`

## Versionierung und automatische Docker-Releases

Ab jetzt gilt:

- jedes neue Git-Tag im Format `vX.Y.Z` triggert automatisch einen Build
- das GitHub-Action-Workflow-File liegt unter `.github/workflows/release-docker.yml`
- bei Tag-Push wird automatisch zu
  - `ghcr.io/<github-owner>/linkwarden-mcp`
  - `docker.io/<dockerhub-user>/linkwarden-mcp`
  gepusht
- verwendete Repository-Secrets:
  - `GHCR_USERNAME`, `GHCR_TOKEN`
  - `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`

Beispiel für neues Release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Sicherheitsmodell

- `/mcp` akzeptiert nur `Authorization: Bearer <API_KEY>`
- API-Keys werden gehasht gespeichert
- Secrets liegen verschlüsselt in `/data/config.enc`
- Schreiboperationen benötigen benutzerspezifischen Write-Mode (`user_settings.write_mode_enabled=true`)
- Reorg ist immer 2-stufig (plan + apply)
- Audit-Log erfasst Actor/Tool/Targets/Before-After/Outcome
- Setup-Bypässe per `adminPassphrase` für Admin-Routen sind entfernt

## Health und Readiness

- `GET /health`: Prozess lebt
- `GET /ready`: Setup + Unlock + User + Target + Whitelist + Linkwarden erreichbar

## Debug-Logging

Die Anwendung loggt strukturiert als JSON auf `stdout` (Container-Logs).
Events umfassen u. a.:

- HTTP Request-Start/Ende inkl. Laufzeit
- Setup/Login/Session/CSRF Entscheidungen
- Admin/User UI-Aktionen
- MCP Auth + JSON-RPC Methoden + Tool-Ausführung
- Linkwarden Upstream Calls inkl. Retry/Timeout

Wichtige Kommandos:

```bash
docker logs -f linkwarden-mcp
```

Bei Portainer: `Containers` -> `linkwarden-mcp` -> `Logs`.

## Weitere Dokumentation

- `/Volumes/dev/linkwarden-mcp/docs/README.md`
