# OIDC / JWKS authentication

## Configuration

```bash
export AEGIS_OIDC_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0
export AEGIS_OIDC_AUDIENCE=api://aegis-swarm
export AEGIS_OIDC_JWKS_URL=https://.../jwks   # optional; default {issuer}/.well-known/jwks.json
```

## Behavior

| Config | Mutating routes |
|--------|-----------------|
| Neither API key nor OIDC | Open (dev) |
| `AEGIS_API_KEY` only | Require `X-API-Key` |
| `AEGIS_OIDC_ISSUER` only | Require `Authorization: Bearer <jwt>` |
| Both | Either credential accepted |

## Validation rules

- Algorithms: RS256/384/512, ES256/384/512 only (no HS*)
- Signature verified against JWKS `kid`
- `iss` must match `AEGIS_OIDC_ISSUER`
- `aud` checked when `AEGIS_OIDC_AUDIENCE` set
- `exp` required
- JWKS cached 1h; forced refresh on unknown `kid` (rotation)
