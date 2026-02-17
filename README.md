# linkwarden-mcp

`linkwarden-mcp` ist ein eigenständiger MCP-Server als Docker-Container für deine Synology/Portainer-Umgebung.
Er verbindet ChatGPT (Developer Mode / Custom MCP Connector) mit deiner selbstgehosteten Linkwarden-Instanz.

## Was der Container macht

- Stellt einen **Remote MCP Server** via **Streamable HTTP** unter `POST /mcp` bereit
- Unterstützt OAuth 2.0 für ChatGPT MCP Connectoren (`/.well-known`, `/authorize`, `/token`)
- Nutzt intern die Linkwarden REST API (`/api/v1/...`)
- Hat eine browserbasierte Admin/User-Oberfläche unter `GET /admin`
- Nutzt `GET /` nur als MCP-Service-Root und OAuth-Login-Bridge nach `/admin?next=...` (keine Root-WebUI)
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
- `MCP_PUBLIC_BASE_URL=https://mcp.deine-domain.tld`
- `MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS=1800`
- `MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS=2592000`
- `MCP_HOST_BIND_IP=127.0.0.1`
- `MCP_HOST_PORT=39227`

Optionaler Direktzugriff per NAS-IP:

- Beispiel: `MCP_HOST_BIND_IP=192.168.123.50`
- dann ist die UI/MCP direkt über `http://192.168.123.50:39227/admin` bzw. `http://192.168.123.50:39227/mcp` erreichbar

Hinweis zu Logs:

- `MCP_LOG_LEVEL=debug` loggt alle Debug-Events (empfohlen für Fehlersuche)
- für ruhigeren Betrieb kannst du auf `info` zurückstellen

## First-Run Setup im Browser

Nach dem ersten Start:

1. Öffne `http://192.168.123.220:8080/admin`
2. Fülle den First-Run Setup-Dialog aus:
   - `masterPassphrase`
   - `adminUsername`
   - `adminPassword`
   - `linkwardenBaseUrl`
   - `Linkwarden API Key -> MCP`
   - optional `OAuth Client ID` + `OAuth Client Secret` (für statischen OAuth-Client)
3. Optional kannst du direkt einen initialen Admin-MCP-Key generieren lassen
4. Danach login mit Admin-Zugang im selben UI

Hinweis:

- Der im Setup eingegebene `Linkwarden API Key -> MCP` wird dem Admin-User zugeordnet.
- Jeder weitere Benutzer muss seinen eigenen Linkwarden API Key setzen (oder der Admin setzt ihn).

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
curl -X POST http://192.168.123.220:8080/admin/setup/unlock \
  -H 'content-type: application/json' \
  -d '{"passphrase":"<dein-master-passphrase>"}'
```

## Admin- und User-Oberfläche (`GET /admin`)

### Admin kann

- Benutzer anlegen/deaktivieren
- Rollen vergeben (`admin`/`user`)
- API-Keys ausstellen/revoken
- Write-Mode pro Benutzer setzen
- Linkwarden-Ziel pflegen
- Linkwarden API Keys pro Benutzer setzen/rotieren

### User kann

- Eigene Daten sehen
- Eigenen Write-Mode ein/ausschalten
- Eigenen Linkwarden API Key -> MCP setzen
- Eigene API-Keys erstellen/revoken

Keine Selbstregistrierung vorhanden.

## ChatGPT Developer Mode: Custom MCP Connector (OAuth)

1. In ChatGPT (Workspace Admin) Developer Mode für MCP Connectoren aktivieren
2. Custom Connector anlegen:
   - Name: `linkwarden-mcp`
   - Server URL: `https://<deine-domain>/mcp`
   - Auth: OAuth 2.0
   - Authorization URL: `https://<deine-domain>/authorize`
   - Token URL: `https://<deine-domain>/token`
   - Scopes: `mcp.read mcp.write offline_access`
   - Optional `Client ID`/`Client Secret`:
   - Wenn im First-Run gesetzt, exakt diese Werte im Connector eintragen.
   - Wenn nicht gesetzt, kann dynamische Client-Registrierung über `/register` genutzt werden.
3. Tool Discovery testen (`tools/list`)

Hinweis:

- Wenn OAuth ohne bestehende Session startet, erfolgt der Login-Bootstrap über Root (`/?next=...`) und wird serverseitig sicher auf `/admin?next=...` umgeleitet.

Beispielprompts:

- `Nutze linkwarden_search_links mit query "mail security"`
- `Erstelle mit linkwarden_plan_reorg eine tag-by-keywords Planung für "spf dkim dmarc mta-sts dane" und zeige Preview`
- `Wende plan_id XYZ mit linkwarden_apply_plan confirm APPLY an`

## Agent-Workflows für deinen Alltag

Der MCP ist jetzt auf deinen gewünschten Arbeitsmodus ausgelegt:

- Links finden (nativ über Linkwarden API):
  - `linkwarden_search_links` nutzt die nativen Linkwarden-Endpunkte.
  - Wenn `limit` weggelassen wird, verarbeitet der MCP alle Treffer (keine harte Obergrenze).
- Collections nativ verwalten:
  - `linkwarden_create_collection`, `linkwarden_update_collection`, `linkwarden_delete_collection`
- Links nativ organisieren:
  - `linkwarden_set_links_collection` für Collection-Zuweisung/Entfernung
  - `linkwarden_set_links_pinned` für Pin/Unpin
  - `linkwarden_clean_link_urls` zum Entfernen von Tracking-Parametern
- Server-Metadaten ausgeben:
  - `linkwarden_get_server_info`
  - liefert Name, Server-Version und MCP-Protokollversion.
- Chat-Links direkt ablegen:
  - `linkwarden_capture_chat_links`
  - extrahiert URLs aus Freitext und legt sie in `ChatGPT Chats > <Chat Name>` ab.
- Nicht funktionale Links beobachten und archivieren:
- Nicht funktionale Links beobachten und per User-Policy verarbeiten:
  - `linkwarden_monitor_offline_links`
  - trackt Reachability-Failures pro Link in SQLite
  - Dry-run zeigt Kandidaten
  - mit `dryRun=false` greift die konfigurierte Policy pro User (`archive`, `delete` oder `none`).
- Alles in einem Lauf:
  - `linkwarden_run_daily_maintenance`
  - kombiniert Reorg-Plan(+optional Apply) und Offline-Monitoring(+optional Archivierung)
  - Standard ist sicher: `apply=false` (nur Vorschau).
  - persistiert Laufstatus in `maintenance_runs` und Step-Details in `maintenance_run_items`.
  - nutzt einen per-User Run-Lock, damit keine parallelen Maintenance-Läufe kollidieren.

Beispiel für Chat-Import:

- `Nutze linkwarden_capture_chat_links mit chatName "SEO Sprint 2026" und text "<hier kompletter Chat-Auszug>"`.

Beispiel für Offline-Monitoring:

- `Nutze linkwarden_monitor_offline_links mit dryRun=true`.
- Danach:
- `Nutze linkwarden_monitor_offline_links mit dryRun=false action="archive" archiveCollectionId=123`.

Beispiel für Versionsabfrage:

- `Nutze linkwarden_get_server_info`.

Beispiel für kompletten Daily-Flow:

- Dry-run:
- `Nutze linkwarden_run_daily_maintenance mit reorg {strategy:"tag-by-keywords", parameters:{rules:[...]}} und offline {offlineDays:14, minConsecutiveFailures:3, archiveCollectionId:123} apply=false`.
- Anwenden:
- `Nutze linkwarden_run_daily_maintenance mit reorg {strategy:"tag-by-keywords", parameters:{rules:[...]}} und offline {offlineDays:14, minConsecutiveFailures:3, archiveCollectionId:123} apply=true confirm="APPLY"`.

Hinweis zu „proaktiv“:

- Der MCP stellt die Tools bereit; die automatische Ausführung passiert über den aufrufenden Agenten/Connector.
- Praktisch: In ChatGPT einen wiederkehrenden Task auf `linkwarden_monitor_offline_links` setzen.
- Für One-shot-Orchestrierung bevorzugt `linkwarden_run_daily_maintenance` und einen separaten Review-Task für Apply.

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

- `/mcp` akzeptiert OAuth-Bearer-Tokens (ChatGPT Connector Standard)
- MCP API Keys bleiben als Legacy-Fallback für manuelle Integrationen verfügbar
- API-Keys werden gehasht gespeichert
- Runtime-Config (inkl. optionaler OAuth Client-Daten) liegt verschlüsselt in `/data/config.enc`
- Pro-User Linkwarden API Keys liegen verschlüsselt in `/data/state.db`
- Pro Benutzer gibt es zwei getrennte Keys:
- `Linkwarden API Key -> MCP` (vom jeweiligen Linkwarden-User)
- `MCP API Key -> AI` (für ChatGPT/AI)
- Schreiboperationen benötigen benutzerspezifischen Write-Mode (`user_settings.write_mode_enabled=true`)
- Reorg ist immer 2-stufig (plan + apply)
- Audit-Log erfasst Actor/Tool/Targets/Before-After/Outcome
- Setup-Bypässe per `adminPassphrase` für Admin-Routen sind entfernt

## Health und Readiness

- `GET /health`: Prozess lebt
- `GET /ready`: Setup + Unlock + User + Target + Linkwarden erreichbar

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
