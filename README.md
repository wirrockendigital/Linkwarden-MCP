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

## Lokale Quality-Gates bei instabiler Toolchain/DNS

Wenn lokale `npm install`/`tsc`/`vitest` durch DNS- oder Toolchain-Probleme auf dem Host instabil sind, kannst du die Checks isoliert in Docker ausführen:

- `npm run lint:docker`
- `npm run build:docker`
- `npm run test:docker`
- `npm run qa:docker` (führt `lint + build + test` aus)

Die Commands nutzen `tools/run-in-docker.sh` und laufen in einem Node-20-Container mit sauberem Temp-Workspace.

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
- `MCP_DEFAULT_QUERY_TIMEZONE=Europe/Berlin`
- `MCP_PERPLEXITY_API_KEY=` (optional; für `inferenceProvider=perplexity`)
- `MCP_MISTRAL_API_KEY=` (optional; für `inferenceProvider=mistral`)
- `MCP_HUGGINGFACE_API_KEY=` (optional; für `inferenceProvider=huggingface`)
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

Die `/admin`-UI ist als role-aware Tab-Navigation aufgebaut:

- Zwei Ebenen (Top-Tab + Sub-Tab) mit stabilen Deep-Links über `#tab=<top>&sub=<sub>`
- Lazy-Loading pro Panel mit Cache + gezielter Revalidierung nach Mutationen
- Einheitliches Feedback über Toasts, Inline-Feldfehler und optionalen Debug-Drawer (JSON)
- Systemweites Theme mit `System | Hell | Dunkel` und Persistenz im Browser
- Keyboard/A11y-Unterstützung für Tab-Navigation (`Arrow`, `Home/End`, `Enter/Space`)

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
- Eigenes Chat-Control für Archiv-Collection und Chat-Capture-Tags setzen
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

- `Nutze linkwarden_query_links mit selector {query:"mail security"} limit 50 fields ["id","title","url"] verbosity "minimal"`
- `Nutze linkwarden_query_links mit selector {createdAtRelative:{amount:1,unit:"month",mode:"previous_calendar"}, timeZone:"Europe/Berlin"} limit 200`
- `Nutze linkwarden_query_links mit selector {tagNamesAny:["Wohnmobil","WoMo"], createdAtRelative:{amount:1,unit:"month",mode:"previous_calendar"}} limit 200`
- `Nutze linkwarden_mutate_links mit selector {collectionId:123, includeDescendants:true} updates {tagMode:"add", tagNames:["security"]} dryRun true`
- `Nutze linkwarden_delete_links mit selector {tagIdsAny:[9]} mode "soft" dryRun false`

## Agent-Workflows für deinen Alltag

Der MCP ist jetzt auf deinen gewünschten Arbeitsmodus ausgelegt:

- Links finden (deterministisch, cursor-basiert):
  - `linkwarden_query_links` mit `selector`, `fields`, `verbosity`, `cursor`.
  - unterstützt `createdAtFrom`, `createdAtTo`, `createdAtRelative`, `timeZone`, `tagNamesAny/tagNamesAll`, `collectionNamesAny`.
  - Namensauflösung für Tags/Collections läuft über exact + Alias (Tags) + striktes Fuzzy-Matching; Details stehen in `warnings`.
- Harte Kennzahlen:
  - `linkwarden_get_stats`, `linkwarden_aggregate_links`.
- Collections nativ verwalten:
  - `linkwarden_create_collection`, `linkwarden_update_collection`, `linkwarden_delete_collection`
- Links nativ organisieren:
  - `linkwarden_mutate_links` für Collection/Tags/Pin/Archive/Rename in einem Tool
  - `linkwarden_assign_tags` für reines Tagging
  - `linkwarden_governed_tag_links` für One-Call Taxonomie-Tagging mit Wildwuchs-Guardrails
  - Governed-Tagging unterstützt nativ `inferenceProvider=builtin|perplexity|mistral|huggingface` (global über Admin-Tagging-Policy)
  - Bei `huggingface` kann ein beliebiges gehostetes Modell über `inferenceModel` gesetzt werden (z. B. `meta-llama/Llama-3.1-8B-Instruct`)
  - `linkwarden_normalize_urls` zum Entfernen von Tracking-Parametern
- Duplikate nativ auflösen:
  - `linkwarden_find_duplicates`, `linkwarden_merge_duplicates`
- Server-Metadaten ausgeben:
  - `linkwarden_get_server_info`
  - liefert Name, Server-Version, MCP-Protokollversion und unterstützte Tag-Inference-Provider.
- Regel-Engine:
  - `linkwarden_create_rule`, `linkwarden_test_rule`, `linkwarden_apply_rule`, `linkwarden_run_rules_now`
  - `linkwarden_list_rules`, `linkwarden_delete_rule`
- Native Auto-Routine für neue Links:
  - `linkwarden_get_new_links_routine_status`
  - `linkwarden_run_new_links_routine_now`
  - User-Backend unter `/admin/ui/user/new-links-routine` für `enabled`, `intervalMinutes`, `modules`, `batchSize`, Backfill-Anfrage/-Bestätigung
- Soft-Delete/ARCHIVE_TAG mit pro-User Archiv-Collection:
  - Backend-Einstellung unter `/admin/ui/user/chat-control` für `archiveCollectionName` und optional `archiveCollectionParentId`
  - Standardname ist `Archive`
  - Wenn die Collection fehlt, wird sie bei Apply automatisch angelegt
  - Bei mehreren Treffern mit gleichem Namen wird deterministisch gewählt: zuerst Root-Collection, sonst kleinste ID
  - Tag `to-delete` wird im Apply-Pfad bei Bedarf automatisch angelegt und gesetzt
- AI-Chat-Link-Capture:
  - `linkwarden_capture_chat_links` speichert Links nach `AI Chats -> <AI Name> -> <Chat Name>`
  - Für einen gewünschten Unterordnernamen `chatName` immer explizit mitschicken; sonst wird der Fallback `Current Chat` verwendet (inkl. Warning im Tool-Output)
  - Collection-Hierarchie wird bei Apply automatisch angelegt, wenn sie fehlt
  - Dedupe erfolgt innerhalb der Ziel-Collection über kanonische URLs
  - Wenn Tag-Validierung beim Erstellen fehlschlägt, wird einmal ohne Tags erneut versucht; Ergebnis wird als Warning plus `summary.createdWithoutTags` ausgewiesen
  - Chat-Control steuert Tag-Verhalten pro User:
    - `chatCaptureTagName` (Default `AI Chat`)
    - `chatCaptureTagAiChatEnabled` (Default `true`)
    - `chatCaptureTagAiNameEnabled` (Default `true`)
- Gespeicherte Queries:
  - `linkwarden_create_saved_query`, `linkwarden_list_saved_queries`, `linkwarden_run_saved_query`
- Audit und Undo:
  - `linkwarden_get_audit`, `linkwarden_undo_operation`

Beispiel für Versionsabfrage:

- `Nutze linkwarden_get_server_info`.

Beispiel für Rule-Flow:

- `Nutze linkwarden_create_rule mit name "Archive 404" selector {...} action {type:"move-to-collection", collectionId:778}`.
- `Nutze linkwarden_test_rule mit id "<rule-id>"`.
- `Nutze linkwarden_apply_rule mit id "<rule-id>" dryRun false`.

Beispiel für AI-Chat-Link-Capture:

- `Nutze linkwarden_capture_chat_links mit chatText "<aktueller Chattext>" aiName "ChatGPT" chatName "Prompt Engineering" dryRun false`.

Hinweis zu „proaktiv“:

- Der MCP stellt die Tools bereit; die automatische Ausführung passiert über den aufrufenden Agenten/Connector.
- Praktisch: In ChatGPT einen wiederkehrenden Task auf `linkwarden_run_rules_now` setzen.
- Für One-shot-Orchestrierung `linkwarden_apply_rule` (einzelne Regel) oder `linkwarden_run_rules_now` (mehrere Regeln) nutzen.

## Versionierung und automatische Docker-Releases

Ab jetzt gilt:

- jeder `git push` (Branch-Push) triggert automatisch einen Build und Push nach GHCR + Docker Hub
- zusätzlich werden bei Git-Tags im Format `vX.Y.Z` Semver-Tags veröffentlicht
- das GitHub-Action-Workflow-File liegt unter `.github/workflows/release-docker.yml`
- es wird automatisch zu
  - `ghcr.io/<github-owner>/linkwarden-mcp`
  - `docker.io/<dockerhub-user>/linkwarden-mcp`
  gepusht
- verwendete Repository-Secrets:
  - `GHCR_USERNAME`, `GHCR_TOKEN`
  - `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`

Beispiel für Branch-Push:

```bash
git push origin main
```

Beispiel für Tag-Release:

```bash
git tag v0.2.9
git push origin v0.2.9
```

## Sicherheitsmodell

- `/mcp` akzeptiert OAuth-Bearer-Tokens (ChatGPT Connector Standard)
- OAuth und MCP API Keys werden nativ parallel unterstützt (ohne Fallback-Pfad)
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
