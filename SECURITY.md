# Security Policy

## Authorized use only

AEGIS Swarm is a **defensive** multi-agent control plane for authorized SOC,
detection engineering, DFIR, and purple-team validation. Operators must have
explicit written authorization for any engagement scope.

Do **not** use this software to attack, exploit, or access systems without
authorization.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | Yes (beta) |
| < 0.4   | Best-effort |

## Reporting a vulnerability

Report security issues privately to the repository owner (GitHub Security
Advisories preferred, or contact the account that owns `Justonejewelry/Aegis-Swarm`).

## Production hardening checklist

- Set `AEGIS_ENV=production`
- Require `AEGIS_API_KEY` and/or OIDC (`AEGIS_OIDC_ISSUER`, audience, JWKS)
- Production **fails closed** if neither API key nor OIDC is configured
- Bind API to private network; put TLS termination / gateway in front
- Restrict `/metrics` and `/redis/status` to scrape networks only
- Never use lab passwords (`aegis_dev_only`) outside local compose
- Set `AEGIS_AUDIT_SIGNING_KEY` for signed audit exports

## Known residual risks (beta)

- Some read endpoints are unauthenticated by design for internal SOC UX
- Default development mode allows unauthenticated mutations when no key/OIDC set
- Lab docker-compose credentials are fixed and public in-repo
