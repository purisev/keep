"""
Generic OIDC auth verifier.

Implements OpenID Connect Core 1.0 only: provider metadata discovery, JWKS
signature validation, and authorization read from token claims. It carries no
knowledge of any particular identity provider — Keycloak, Okta, Entra ID,
Authentik and Zitadel all work through the same configuration, because anything
provider-shaped is expressed as a configurable claim path rather than as code.

Configuration:

    KEEP_OIDC_ISSUER            issuer URL; used for discovery and `iss` validation
    KEEP_OIDC_JWKS_URL          skip discovery and use this JWKS endpoint
    KEEP_OIDC_AUDIENCE          expected `aud`; when empty, `aud` is not verified
    KEEP_OIDC_ALGORITHMS        comma-separated, default RS256
    KEEP_OIDC_EMAIL_CLAIM       default "email", falls back to preferred_username, sub
    KEEP_OIDC_TENANT_CLAIM      default "keep_tenant_id"
    KEEP_OIDC_GROUPS_CLAIM      dotted path, default "groups"
    KEEP_OIDC_ROLE_CLAIM        dotted path to a role name; wins over group mapping
    KEEP_OIDC_ROLE_MAPPINGS     JSON list, ordered by precedence:
                                [{"group": "keep-admins", "role": "admin"}, ...]
    KEEP_OIDC_ROLE_MAPPINGS_FILE  same content as JSON or YAML in a file
    KEEP_OIDC_DEFAULT_ROLE      role for a user matching no mapping; empty = deny

Provider-specific claim paths are configuration, not code. For example, Keycloak
realm roles live at "realm_access.roles" and client roles at
"resource_access.<client-id>.roles"; set KEEP_OIDC_GROUPS_CLAIM accordingly.
"""

import json
import logging
import os

import jwt
import requests
import yaml
from fastapi import HTTPException

from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.authverifierbase import AuthVerifierBase
from keep.identitymanager.rbac import (
    get_or_register_composite_role,
    get_role_by_role_name,
)

logger = logging.getLogger(__name__)

DISCOVERY_PATH = "/.well-known/openid-configuration"
DISCOVERY_TIMEOUT = 10

# get_auth_verifier() is called once per protected route, so discovery and the
# JWKS client are cached per process rather than per verifier instance.
_JWKS_URL_CACHE: dict[str, str] = {}
_JWKS_CLIENT_CACHE: dict[str, jwt.PyJWKClient] = {}


class OidcConfigurationError(Exception):
    """Raised when the verifier cannot be configured from the environment."""


def _claim(payload: dict, path: str):
    """Read a dotted claim path out of a decoded token."""
    node = payload
    for part in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
        if node is None:
            return None
    return node


def _as_list(value) -> list[str]:
    """
    Normalise a groups claim.

    Providers disagree here: some emit a JSON array, some a single string, and
    some a comma-separated string once group-to-claim mapping is configured.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _discover_jwks_url(issuer: str) -> str:
    if issuer in _JWKS_URL_CACHE:
        return _JWKS_URL_CACHE[issuer]
    url = f"{issuer.rstrip('/')}{DISCOVERY_PATH}"
    try:
        response = requests.get(url, timeout=DISCOVERY_TIMEOUT)
        response.raise_for_status()
        metadata = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise OidcConfigurationError(
            f"OIDC discovery failed for {url}: {exc}. "
            "Set KEEP_OIDC_JWKS_URL to skip discovery."
        ) from exc
    jwks_url = metadata.get("jwks_uri")
    if not jwks_url:
        raise OidcConfigurationError(f"No jwks_uri in provider metadata at {url}")
    _JWKS_URL_CACHE[issuer] = jwks_url
    logger.info("Discovered JWKS endpoint %s for issuer %s", jwks_url, issuer)
    return jwks_url


def _load_role_mappings() -> list[tuple[str, str]]:
    """
    Load ordered group-to-role mappings.

    Order is precedence: the first mapping whose group is present on the token
    wins. That is deliberate — it lets a custom role outrank a built-in one,
    which a fixed priority list cannot express.
    """
    raw: list = []

    path = os.environ.get("KEEP_OIDC_ROLE_MAPPINGS_FILE", "").strip()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                parsed = yaml.safe_load(handle) or []
        except (OSError, yaml.YAMLError) as exc:
            raise OidcConfigurationError(
                f"Cannot read KEEP_OIDC_ROLE_MAPPINGS_FILE {path!r}: {exc}"
            ) from exc
        if isinstance(parsed, dict):
            parsed = parsed.get("mappings", [])
        raw.extend(parsed or [])

    inline = os.environ.get("KEEP_OIDC_ROLE_MAPPINGS", "").strip()
    if inline:
        try:
            parsed = json.loads(inline)
        except ValueError as exc:
            raise OidcConfigurationError(
                f"Cannot parse KEEP_OIDC_ROLE_MAPPINGS as JSON: {exc}"
            ) from exc
        if isinstance(parsed, dict):
            parsed = parsed.get("mappings", [])
        raw.extend(parsed or [])

    mappings: list[tuple[str, str]] = []
    for entry in raw:
        if not isinstance(entry, dict) or "group" not in entry or "role" not in entry:
            raise OidcConfigurationError(
                f"Role mapping must be {{'group': ..., 'role': ...}}, got {entry!r}"
            )
        mappings.append((str(entry["group"]), str(entry["role"])))
    return mappings


class OidcAuthVerifier(AuthVerifierBase):
    """Validates OIDC bearer tokens and resolves a Keep role from claims."""

    def __init__(self, scopes: list[str] = []) -> None:
        super().__init__(scopes)
        self.issuer = os.environ.get("KEEP_OIDC_ISSUER", "").strip().rstrip("/")
        self.audience = os.environ.get("KEEP_OIDC_AUDIENCE", "").strip()
        self.algorithms = [
            algorithm.strip()
            for algorithm in os.environ.get("KEEP_OIDC_ALGORITHMS", "RS256").split(",")
            if algorithm.strip()
        ]
        self.email_claim = os.environ.get("KEEP_OIDC_EMAIL_CLAIM", "email")
        self.tenant_claim = os.environ.get("KEEP_OIDC_TENANT_CLAIM", "keep_tenant_id")
        self.groups_claim = os.environ.get("KEEP_OIDC_GROUPS_CLAIM", "groups")
        self.role_claim = os.environ.get("KEEP_OIDC_ROLE_CLAIM", "").strip()
        self.default_role = os.environ.get("KEEP_OIDC_DEFAULT_ROLE", "").strip()
        self.role_mappings = _load_role_mappings()
        # "first-match" (default): the first mapping whose group is on the
        # token wins — ordering is the precedence. "union": every matching
        # mapping contributes, and a token matching several roles gets a
        # composite whose scopes and resource permissions are the union of
        # the members' (a user in two teams sees both feeds natively).
        self.role_composition = (
            os.environ.get("KEEP_OIDC_ROLE_COMPOSITION", "first-match")
            .strip()
            .lower()
        )
        if self.role_composition not in ("first-match", "union"):
            raise OidcConfigurationError(
                "KEEP_OIDC_ROLE_COMPOSITION must be 'first-match' or 'union', "
                f"got {self.role_composition!r}"
            )

        jwks_url = os.environ.get("KEEP_OIDC_JWKS_URL", "").strip()
        if not jwks_url:
            if not self.issuer:
                raise OidcConfigurationError(
                    "Set KEEP_OIDC_ISSUER, or KEEP_OIDC_JWKS_URL to skip discovery"
                )
            jwks_url = _discover_jwks_url(self.issuer)
        self.jwks_url = jwks_url

        if jwks_url not in _JWKS_CLIENT_CACHE:
            # cache_keys=True matters more than it looks. The default
            # (cache_keys=False, cache_jwk_set=True) caches only the raw JWKS
            # JSON, so get_jwk_set() runs PyJWKSet.from_dict() on every call and
            # reconstructs the RSA key objects for every key in the set -- on
            # every request, since the UI polls. With it on, get_signing_key(kid)
            # is wrapped in lru_cache(maxsize=max_cached_keys) and returns an
            # already-parsed PyJWK.
            #
            # The trade-off: that cache outlives key rotation, so a revoked kid
            # keeps being served until it is evicted (16 entries). Harmless --
            # the signature is still verified against it, and a token signed by
            # a rotated-out key fails as it should.
            _JWKS_CLIENT_CACHE[jwks_url] = jwt.PyJWKClient(jwks_url, cache_keys=True)
        self.jwks_client = _JWKS_CLIENT_CACHE[jwks_url]

        if not self.role_mappings and not self.role_claim and not self.default_role:
            # Every token would be rejected; say so now rather than at first login.
            raise OidcConfigurationError(
                "No authorization source configured: set at least one of "
                "KEEP_OIDC_ROLE_MAPPINGS, KEEP_OIDC_ROLE_CLAIM, KEEP_OIDC_DEFAULT_ROLE"
            )

        self.logger.info(
            "OIDC auth verifier initialized",
            extra={
                "issuer": self.issuer,
                "jwks_url": self.jwks_url,
                "groups_claim": self.groups_claim,
                "mappings": len(self.role_mappings),
            },
        )

    def _resolve_role(self, payload: dict) -> str:
        # 1. An explicit role claim wins, when the provider is trusted to set it.
        if self.role_claim:
            role_name = _claim(payload, self.role_claim)
            if isinstance(role_name, list):
                role_name = role_name[0] if role_name else None
            if role_name:
                return str(role_name)

        # 2. Ordered group mappings. In first-match mode the order is the
        # precedence; in union mode every match contributes and two or more
        # distinct roles become a composite (scopes and resource permissions
        # union — see rbac.get_or_register_composite_role and
        # oidc_permissions.get_rules_for).
        groups = _as_list(_claim(payload, self.groups_claim))
        self.logger.debug("OIDC groups on token: %s", groups)
        matched: list[str] = []
        for group, role_name in self.role_mappings:
            if group in groups:
                if self.role_composition == "first-match":
                    return role_name
                if role_name not in matched:
                    matched.append(role_name)
        if len(matched) == 1:
            return matched[0]
        if matched:
            return get_or_register_composite_role(matched)

        # 3. Configured fallback, if any.
        if self.default_role:
            return self.default_role

        self.logger.warning("No role mapping matched groups %s", groups)
        raise HTTPException(
            status_code=403, detail="No Keep role mapped for this user's groups"
        )

    # Deliberately not cached, unlike the resource-permission resolution in
    # oidc_permission_cache.py. Caching token -> AuthenticatedEntity would save
    # one RSA verification, while a cache entry outliving the token's `exp`
    # would keep an expired token working for the rest of the TTL. Wrong trade.
    def _verify_bearer_token(self, token: str) -> AuthenticatedEntity:
        if not token:
            raise HTTPException(status_code=401, detail="No token provided")

        try:
            signing_key = self.jwks_client.get_signing_key_from_jwt(token).key
            payload = jwt.decode(
                token,
                key=signing_key,
                algorithms=self.algorithms,
                audience=self.audience or None,
                issuer=self.issuer or None,
                options={
                    "verify_exp": True,
                    "verify_aud": bool(self.audience),
                    "verify_iss": bool(self.issuer),
                },
            )
        except jwt.ExpiredSignatureError:
            self.logger.warning("OIDC token has expired")
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError as exc:
            self.logger.warning("Invalid OIDC token: %s", exc)
            raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")
        except HTTPException:
            raise
        except Exception as exc:
            self.logger.exception("Failed to validate OIDC token")
            raise HTTPException(
                status_code=401, detail=f"Token validation failed: {exc}"
            )

        email = (
            _claim(payload, self.email_claim)
            or payload.get("preferred_username")
            or payload.get("sub")
        )
        if not email:
            raise HTTPException(status_code=401, detail="No identity claim in token")

        role_name = self._resolve_role(payload)
        # Fail here with a precise message rather than deep in _authorize().
        get_role_by_role_name(role_name)

        tenant_id = _claim(payload, self.tenant_claim) or SINGLE_TENANT_UUID
        self.logger.debug("Authenticated %s as role %s", email, role_name)
        return AuthenticatedEntity(
            tenant_id=str(tenant_id),
            email=str(email),
            role=role_name,
            token=token,
        )
