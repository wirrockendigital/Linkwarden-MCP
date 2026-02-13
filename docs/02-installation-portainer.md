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

Nach dem Deploy öffnest du intern `http://192.168.123.220:8080/` für Setup/Login.
