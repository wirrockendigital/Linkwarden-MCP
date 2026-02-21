# 02 - Installation mit Portainer (Synology)

## Voraussetzungen

- Portainer läuft auf deiner Synology
- Docker-Netzwerk `allmydocker-net` existiert
- Subnetz enthält `192.168.123.220`
- Linkwarden intern erreichbar (z. B. `http://linkwarden:3000`)

## Verwendete Dateien

- Stack: `/Volumes/dev/linkwarden-mcp/linkwarden-mcp.yaml`
- Env: `/Volumes/dev/linkwarden-mcp/linkwarden-mcp.env`

## Deployment

1. Portainer öffnen -> `Stacks` -> `Add stack`
2. Inhalt aus `linkwarden-mcp.yaml` einfügen
3. Unter `Environment variables` `linkwarden-mcp.env` hochladen
4. Deploy ausführen

## Netz und feste IP

Der Container läuft mit statischer IP:

- `192.168.123.220`

Konfiguration über Env:

- `MCP_DOCKER_NETWORK=allmydocker-net`
- `MCP_STATIC_IP=192.168.123.220`
- `MCP_RUN_UID=1061`
- `MCP_RUN_GID=1061`
- `MCP_HOST_BIND_IP=127.0.0.1`
- `MCP_HOST_PORT=39227`
- `MCP_PUBLIC_BASE_URL=https://mcp.deine-domain.tld`
- `MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS=1800`

Die OAuth Refresh-Session-Laufzeit wird im Admin-Backend gesetzt:

- `Integrationen -> Linkwarden Ziel -> OAuth Session-Laufzeit`
- Presets: `Dauerhaft`, `Täglich`, `Wöchentlich`, `30`, `180`, `365` Tage

Der Container wird mit diesen Werten gestartet:

- `user: "${MCP_RUN_UID}:${MCP_RUN_GID}"`

## Persistente Daten

- Host: `MCP_VOLUME_HOST=/volume2/docker/linkwarden-mcp/data`
- Container: `MCP_VOLUME_CONTAINER=/data`

## Auto-Unlock Datei

- Host-Datei: `MCP_MASTER_PASSPHRASE_HOST_FILE=/volume2/docker/linkwarden-mcp/master.passphrase`
- Container-Datei: `MCP_MASTER_PASSPHRASE_FILE=/run/secrets/linkwarden-mcp-master-passphrase`

Die Datei muss die Master-Passphrase als eine Zeile enthalten.

## Reverse Proxy (DSM)

Empfohlen:

- Extern: `https://mcp.deine-domain.tld`
- Intern: `http://192.168.123.220:8080`
- `MCP_PUBLIC_BASE_URL` muss auf die externe HTTPS-URL zeigen, damit OAuth-Metadata korrekt ist.

Nach dem Deploy öffnest du intern `http://192.168.123.220:8080/` für Setup/Login.

## Optional: Direkter Zugriff per NAS-IP:Port

Für direkten Zugriff ohne Reverse Proxy:

1. In `linkwarden-mcp.env` `MCP_HOST_BIND_IP` auf deine NAS-IP setzen (oder `0.0.0.0`)
2. `MCP_HOST_PORT` auf dem unüblichen Default `39227` lassen (oder anpassen)
3. Stack neu deployen

Danach erreichst du den Dienst direkt über:

- `http://<NAS-IP>:39227`
