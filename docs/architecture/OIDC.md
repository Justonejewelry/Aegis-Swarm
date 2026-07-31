# OIDC / JWKS authentication

## Configuration

```bash
export AEGIS_OIDC_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0
export AEGIS_OIDC_AUDIENCE=api://aegis-swarm
export AEGIS_OIDC_JWKS_URL=https://.../jwks   # optional
export AEGIS_OIDC_APPROVER_ROLES=soc-lead,admin,approver
```

## JWKS resolution order

1. `AEGIS_OIDC_JWKS_URL` if set
2. `{issuer}/.well-known/openid-configuration` → `jwks_uri`
3. Fallback: `{issuer}/.well-known/jwks.json`

## Approve / Abort

Requires one of `AEGIS_OIDC_APPROVER_ROLES` when OIDC is enabled.
Matching `X-API-Key` still bypasses (break-glass / automation).
