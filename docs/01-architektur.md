# 01 - Architektur

## Überblick

`linkwarden-mcp` ist ein Remote-MCP-Server zwischen ChatGPT und Linkwarden.

Datenfluss:

1. ChatGPT Connector nutzt OAuth 2.0 (`/authorize`, `/token`) und sendet MCP-Requests an `POST /mcp`
2. `linkwarden-mcp` authentifiziert den Benutzer primär über OAuth Bearer Token (API-Key nur Legacy-Fallback)
3. Tool-Aufrufe werden gegen Linkwarden (`/api/v1/...`) ausgeführt
4. Antworten gehen als MCP Tool-Result zurück

## Persistenz

- `/data/config.enc`: verschlüsselte Runtime-Settings (Timeouts, Retries, Plan-TTL)
- `/data/state.db`: SQLite für
  - Users
  - User Settings (Write-Mode pro User)
  - API Keys
  - Linkwarden API Keys pro User (verschlüsselt)
  - Sessions
  - Linkwarden Target + Whitelist
  - Reorg-Pläne / Plan-Runs
  - Audit-Log

## Betriebsendpunkte

- `GET /` -> Setup/Login/Dashboard UI
- `POST /mcp` -> Streamable HTTP MCP
- `GET /.well-known/oauth-protected-resource` -> OAuth Resource Metadata
- `GET /.well-known/oauth-authorization-server` -> OAuth Authorization Server Metadata
- `GET /authorize` -> OAuth Authorization Endpoint
- `POST /token` -> OAuth Token Endpoint
- `POST /register` -> optionale Dynamic Client Registration
- `GET /health` -> Liveness
- `GET /ready` -> Readiness
- `POST /setup/initialize` -> First-Run Setup
- `POST /setup/unlock` -> Fallback Unlock

## Warum Streamable HTTP

- passt direkt zu ChatGPT Custom MCP Connector
- einfacher Reverse-Proxy-Betrieb als SSE
- klare Request/Response-Semantik
