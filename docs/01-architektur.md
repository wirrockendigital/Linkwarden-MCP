# 01 - Architektur

## Überblick

`linkwarden-mcp` ist ein Remote-MCP-Server zwischen ChatGPT und Linkwarden.

Datenfluss:

1. ChatGPT Connector sendet MCP-Requests an `POST /mcp`
2. `linkwarden-mcp` authentifiziert den Benutzer über Bearer API-Key
3. Tool-Aufrufe werden gegen Linkwarden (`/api/v1/...`) ausgeführt
4. Antworten gehen als MCP Tool-Result zurück

## Persistenz

- `/data/config.enc`: verschlüsselte Runtime-Secrets (Linkwarden API Token)
- `/data/state.db`: SQLite für
  - Users
  - User Settings (Write-Mode pro User)
  - API Keys
  - Sessions
  - Linkwarden Target + Whitelist
  - Reorg-Pläne / Plan-Runs
  - Audit-Log

## Betriebsendpunkte

- `GET /` -> Setup/Login/Dashboard UI
- `POST /mcp` -> Streamable HTTP MCP
- `GET /health` -> Liveness
- `GET /ready` -> Readiness
- `POST /setup/initialize` -> First-Run Setup
- `POST /setup/unlock` -> Fallback Unlock

## Warum Streamable HTTP

- passt direkt zu ChatGPT Custom MCP Connector
- einfacher Reverse-Proxy-Betrieb als SSE
- klare Request/Response-Semantik

