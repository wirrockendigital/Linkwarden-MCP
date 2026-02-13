# 06 - Sicherheitsmodell

## Secret-Handling

- Keine hardcodierten Secrets
- Linkwarden-Token liegt verschlüsselt in `/data/config.enc`
- Verschlüsselung über Master-Passphrase (AES-GCM + PBKDF2)
- API-Keys werden nur gehasht gespeichert

## Authentifizierung

### MCP

- `Authorization: Bearer <MCP_API_KEY>` auf `/mcp`
- Token ist einem Benutzerkonto zugeordnet

### Browser-UI

- Session-Login mit Username/Passwort
- Session-Cookie: `HttpOnly`, `SameSite=Strict`, `Secure` (bei HTTPS/Config)
- CSRF-Schutz per Double-Submit-Token (`mcp_csrf` + `x-csrf-token`)
- Login-Rate-Limit pro IP+Username

## Write-Schutz

Write-Tools sind nur erlaubt wenn:

1. Benutzerrolle `admin` oder `user`
2. eigener Write-Mode aktiv (`user_settings.write_mode_enabled=true`)

## Dry-run + Apply

- Reorg immer über `linkwarden_plan_reorg` (dry-run)
- Ausführung nur über `linkwarden_apply_plan` mit `confirm="APPLY"`
- Plan muss gültig sein (nicht expired, nicht bereits applied)

## Whitelist-Enforcement

- Aktive Linkwarden Base URL muss strikt in Whitelist liegen
- Erlaubte Typen: `domain`, `ip`, `cidr`
- Verboten: Wildcards, `0.0.0.0/0`, `::/0`

## Audit-Log

Jeder Write wird protokolliert mit:

- Actor (inkl. user/apiKey-Kontext)
- Toolname
- Zielobjekten
- Before/After Summary
- Outcome (success/failed)

