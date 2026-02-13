# AGENTS.md

Diese Datei definiert die Arbeitsregeln für Agents und Entwickler in diesem Repository.

## Ziel des Projekts

`linkwarden-mcp` ist ein Remote-MCP-Server, der ChatGPT-Connectoren sicheren Zugriff auf die Linkwarden REST API gibt.
Der Server ist als Multi-User-System aufgebaut (eigene API-Keys pro Benutzer).

## Stack

- Node.js 20+
- TypeScript
- Fastify
- SQLite (`better-sqlite3`)
- Zod für Input-Validierung

## Repository-Struktur

- `src/` Anwendungslogik
- `test/` Unit-Tests
- `Dockerfile` Container-Build
- `linkwarden-mcp.yaml` Portainer Stack
- `linkwarden-mcp.env` Portainer-Umgebungsdatei
- `README.md` Endnutzer-Dokumentation
- `milestone.md` Fortschrittsprotokoll

## Verbindliche Konventionen

- Code und Code-Kommentare sind auf Englisch.
- Nutzerdokumentation ist auf Deutsch.
- Portainer-Dateien sind nach Projekt benannt: `<projektname>.yaml` und `<projektname>.env`.
- Keine Secrets in Quellcode oder statischen Env-Dateien committen.
- Secrets werden ausschließlich über den First-Run-Setup-Flow verschlüsselt in `/data/config.enc` gespeichert.
- Jede relevante Implementierungsänderung wird in `milestone.md` protokolliert.

## Sicherheitsregeln

- Write-Operationen nur bei aktiviertem Write-Mode.
- Reorganisationen immer über Dry-run Plan + explizites `confirm=APPLY`.
- MCP-Zugriff nur mit Bearer-Token.
- API-Keys werden nur gehasht in SQLite gespeichert; Klartext-Tokens nur bei Erstellung ausgeben.
- Tokens und Passphrasen dürfen niemals geloggt oder in Tool-Ausgaben zurückgegeben werden.

## Qualitätsanforderungen

- Änderungen an Input-/Tool-Schemas brauchen passende Tests.
- Änderungen an Krypto-, Auth- oder Plan-Logik brauchen Unit-Tests.
- Vor Release: `npm run lint`, `npm run test`, `npm run build`.

## Deployment-Fokus

Primärer Zielbetrieb ist Synology NAS mit Portainer Stack Deployment und DSM Reverse Proxy.
