"""Authentication helpers — API key and OIDC/JWKS."""
from aegis.auth.api_key import require_api_key
from aegis.auth.deps import require_auth
from aegis.auth.oidc import Principal, optional_oidc_principal, require_oidc_principal, verify_bearer_token

__all__ = [
    "Principal",
    "optional_oidc_principal",
    "require_api_key",
    "require_auth",
    "require_oidc_principal",
    "verify_bearer_token",
]
