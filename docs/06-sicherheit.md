# 06 - Sicherheitsmodell

## Secret-Handling

- Keine hardcodierten Secrets
- Linkwarden API Keys liegen pro Benutzer verschlüsselt in `/data/state.db`
- Verschlüsselung über Master-Passphrase (AES-GCM + PBKDF2)
- API-Keys werden nur gehasht gespeichert

## Authentifizierung

### MCP

- OAuth 2.0 Bearer Token auf `/mcp` (Standard für ChatGPT Connector)
- MCP API-Key ist nativ gleichwertig zu OAuth angebunden
- Token ist immer einem Benutzerkonto zugeordnet
- Tool-Scopes und Collection-Scopes werden für API-Key und OAuth ausgewertet
- Bei fehlendem/ungültigem Token liefert `/mcp` einen OAuth-kompatiblen `WWW-Authenticate`-Challenge

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

- Bulk-Tools bieten standardmäßig `dryRun=true` (`mutate`, `delete`, `normalize`, `governed_tag_links`)
- Idempotente Writes nutzen optional `idempotencyKey`
- Persistente Regeln werden über `linkwarden_create_rule`, `linkwarden_test_rule`, `linkwarden_apply_rule`, `linkwarden_run_rules_now` gesteuert

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
