"""
Generic OIDC identity manager.

The identity provider is authoritative for users and groups, and this manager
deliberately does not reach into it: no admin API, no directory calls, nothing
provider-specific. Users are listed from Keep's own database, populated as
people sign in. Everything else is a read-only view.

That boundary is what keeps the connector vendor-agnostic — the entire contract
with the provider is "a signed token with claims", which every OIDC provider
implements identically. Provisioning users or editing groups belongs in the
provider's own tooling.

Resource-level authorization follows the same philosophy: which resources a role
may see is configuration in Git, not state in a database. See oidc_permissions.py
for the rule schema and README.md for the environment variables.
"""

from fastapi import HTTPException

from keep.api.core.db import get_users as get_users_from_db
from keep.api.models.user import PermissionEntity, ResourcePermission, Role, User
from keep.contextmanager.contextmanager import ContextManager
from keep.identitymanager.authenticatedentity import AuthenticatedEntity
from keep.identitymanager.identity_managers.oidc.oidc_authverifier import (
    OidcAuthVerifier,
)
from keep.identitymanager.identity_managers.oidc.oidc_permissions import (
    SUPPORTED_RESOURCE_TYPES,
    get_all_rules,
)
from keep.identitymanager.identity_managers.oidc.oidc_resource_resolver import (
    resolve_allowed_resource_ids,
)
from keep.identitymanager.identitymanager import BaseIdentityManager
from keep.identitymanager.rbac import get_all_roles


class OidcIdentityManager(BaseIdentityManager):
    def __init__(self, tenant_id, context_manager: ContextManager = None, **kwargs):
        super().__init__(tenant_id, context_manager, **kwargs)
        self.logger.info("OIDC Identity Manager initialized")

    # OIDC is already the mechanism the user authenticated through, not a
    # provider connected via a separate wizard, so there is nothing for this
    # flag to expose. `support_sso = True` without the underlying
    # get_sso_providers()/get_sso_wizard_url() implementations is what made
    # GET /settings/sso 500 for every OIDC-authenticated session.
    @property
    def support_sso(self) -> bool:
        return False

    def get_auth_verifier(self, scopes) -> OidcAuthVerifier:
        return OidcAuthVerifier(scopes)

    def get_users(self) -> list[User]:
        return [
            User(
                email=user.username,
                name=user.username,
                role=user.role,
                last_login=str(user.last_sign_in) if user.last_sign_in else None,
                created_at=str(user.created_at),
            )
            for user in get_users_from_db()
        ]

    def get_roles(self) -> list[Role]:
        # BaseIdentityManager.get_roles() reads a module-level snapshot of rbac
        # taken at import time. Reading the registry here instead keeps custom
        # roles visible regardless of import order.
        roles = []
        for role_name, role_class in get_all_roles().items():
            roles.append(
                Role(
                    id=role_name,
                    name=role_name,
                    description=getattr(role_class, "DESCRIPTION", ""),
                    scopes=list(role_class.SCOPES),
                    predefined=role_name in ("admin", "noc", "webhook", "workflowrunner"),
                )
            )
        return roles

    # User lifecycle belongs to the identity provider, not to Keep.
    def create_user(self, **kwargs) -> User:
        return None

    def delete_user(self, user_email=None, **kwargs) -> User:
        return None

    # ----------------------------------------------------------------------- #
    # Resource-level authorization
    #
    # Rules live in configuration (see oidc_permissions.py) and are matched by
    # attribute, so a resource created after the rule was written is covered
    # automatically. A role with no rules for a resource type is unrestricted,
    # which is the contract the call sites document:
    #     # Note: if no limitations (allowed_preset_ids is []), then all presets
    #     # are allowed
    # ----------------------------------------------------------------------- #

    def get_user_permission_on_resource_type(
        self, resource_type: str, authenticated_entity: AuthenticatedEntity
    ) -> list:
        """
        IDs of `resource_type` the entity may see; an empty list means no limit.

        Errors are deliberately not caught here. Since an empty list means
        "unrestricted", turning a failure into an empty list would grant access
        to everything; letting it raise turns it into a 500 instead.
        """
        if resource_type not in SUPPORTED_RESOURCE_TYPES:
            # Nothing can be configured for it, so nothing can be restricted.
            return []
        return resolve_allowed_resource_ids(
            tenant_id=authenticated_entity.tenant_id or self.tenant_id,
            role=authenticated_entity.role,
            resource_type=resource_type,
        )

    def check_permission(
        self, resource_id: str, scope: str, authenticated_entity: AuthenticatedEntity
    ) -> None:
        """
        Raise 403 when the entity's role is restricted and `resource_id` is not
        in its allowed set. Consistent with the inline check in preset.py.
        """
        # Scopes are "{verb}:{resource}"; the resource part names the type.
        resource_type = scope.rsplit(":", 1)[-1] if scope else ""
        if resource_type not in SUPPORTED_RESOURCE_TYPES:
            return
        allowed_ids = self.get_user_permission_on_resource_type(
            resource_type=resource_type,
            authenticated_entity=authenticated_entity,
        )
        if allowed_ids and str(resource_id) not in allowed_ids:
            raise HTTPException(
                status_code=403,
                detail=f"Not authorized to access this {resource_type}",
            )

    def get_permissions(self) -> list[ResourcePermission]:
        """
        Read-only view of the configured rules, for the settings UI.

        One ResourcePermission per rule. resource_id is synthetic and stable for
        a given configuration; it is not a real resource ID, because a rule
        describes a set of resources rather than one. PermissionEntity.type is
        "role" — the upstream DTO documents 'user' or 'group', but neither is
        true here and inventing one would misrepresent the configuration.
        """
        permissions = []
        counters: dict[tuple[str, str], int] = {}
        for rule in get_all_rules():
            key = (rule.resource_type, rule.role)
            index = counters.get(key, 0)
            counters[key] = index + 1
            permissions.append(
                ResourcePermission(
                    resource_id=f"{rule.resource_type}:{rule.role}:{index}",
                    resource_name=rule.describe(),
                    resource_type=rule.resource_type,
                    permissions=[
                        PermissionEntity(id=rule.role, type="role", name=rule.role)
                    ],
                )
            )
        return permissions

    def create_permissions(self, permissions: list[ResourcePermission]) -> None:
        """
        Not supported: the configuration in Git is the only source of truth.

        Failing loudly matters more than it looks. The base implementation is a
        no-op, so an admin editing permissions in the UI would get "Permissions
        created successfully" and believe a restriction is in place when nothing
        was written anywhere.
        """
        raise HTTPException(
            status_code=501,
            detail=(
                "Resource permissions are managed through configuration "
                "(KEEP_RESOURCE_PERMISSIONS / KEEP_RESOURCE_PERMISSIONS_FILE) "
                "and cannot be changed at runtime"
            ),
        )

    # Resources are not registered anywhere: rules match on attributes of rows
    # that already exist in Keep's database, so there is no external
    # authorization model to keep in sync. No-op is the correct behaviour, not a
    # gap.
    def create_resource(
        self, resource_id: str, resource_name: str, scopes: list[str]
    ) -> None:
        pass

    def delete_resource(self, resource_id: str) -> None:
        pass
