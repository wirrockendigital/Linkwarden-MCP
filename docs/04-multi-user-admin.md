# 04 - Multi-User und Admin

## Rollenmodell

Es gibt exakt zwei Rollen:

- `admin`
- `user`

## Wichtige Regeln

- Keine Selbstregistrierung
- Nur `admin` kann Benutzer anlegen/deaktivieren
- Jeder Benutzer hat einen eigenen Write-Mode (`user_settings.write_mode_enabled`)
- MCP-Write-Tools sind nur erlaubt, wenn der jeweilige Benutzer seinen Write-Mode aktiviert hat

## Admin-Funktionen im UI (`GET /`)

- Benutzerliste anzeigen
- Benutzer anlegen (Rolle + Initialpasswort)
- Benutzer aktiv/deaktiv setzen
- Write-Mode je Benutzer setzen
- API-Keys ausstellen und revoken
- Linkwarden API Key -> MCP pro Benutzer setzen/rotieren
- Linkwarden Target/Whitelist verwalten

## User-Funktionen im UI (`GET /`)

- Eigene Profildaten einsehen
- Eigenen Write-Mode schalten
- Eigenen Linkwarden API Key -> MCP setzen
- Eigene API-Keys erstellen/revoken

## API-Routen (session-geschützt)

Admin:

- `GET /ui/admin/users`
- `POST /ui/admin/users`
- `POST /ui/admin/users/:userId/active`
- `POST /ui/admin/users/:userId/write-mode`
- `POST /ui/admin/users/:userId/linkwarden-token`
- `GET /ui/admin/api-keys`
- `POST /ui/admin/api-keys`
- `POST /ui/admin/api-keys/:keyId/revoke`
- `GET /ui/admin/linkwarden`
- `POST /ui/admin/linkwarden`
- `GET /ui/admin/whitelist`
- `POST /ui/admin/whitelist`

User:

- `GET /ui/user/me`
- `POST /ui/user/write-mode`
- `POST /ui/user/linkwarden-token`
- `GET /ui/user/api-keys`
- `POST /ui/user/api-keys`
- `POST /ui/user/api-keys/:keyId/revoke`
