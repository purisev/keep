# Generic OIDC identity manager

A vendor-agnostic identity manager for Keep. It speaks OpenID Connect Core 1.0
and nothing else: provider metadata discovery, JWKS signature validation, and
authorization read from token claims. Keycloak, Okta, Entra ID, Authentik and
Zitadel all work through the same configuration, because everything
provider-shaped is expressed as a configurable claim path rather than as code.

Enable it with `AUTH_TYPE=oidc`.

The identity provider stays authoritative for users and groups. This connector
never calls a provider admin API, never provisions users and never edits groups.
Users are listed from Keep's own database as people sign in; everything else is
a read-only view.

Three things are configured here:

1. **Token validation** — where the keys come from and what must be true of a
   token (`KEEP_OIDC_*`).
2. **Roles** — which Keep role a user gets, and which scopes that role has
   (`KEEP_OIDC_ROLE_*`, `KEEP_CUSTOM_ROLES*`).
3. **Resource permissions** — which incidents and presets a role may see
   (`KEEP_RESOURCE_PERMISSIONS*`).

## Files

| File | Purpose |
| --- | --- |
| `oidc_authverifier.py` | Validates the bearer token and resolves a Keep role from claims |
| `oidc_identitymanager.py` | The identity manager: users, roles, resource permissions |
| `oidc_permissions.py` | Resource permission rules: config, validation, matching |
| `oidc_resource_resolver.py` | Resolves rules to concrete resource IDs against the database |

## Environment variables

### Token validation

| Variable | Default | Meaning |
| --- | --- | --- |
| `KEEP_OIDC_ISSUER` | — | Issuer URL. Used for discovery (`/.well-known/openid-configuration`) and for `iss` validation. Required unless `KEEP_OIDC_JWKS_URL` is set. |
| `KEEP_OIDC_JWKS_URL` | — | Use this JWKS endpoint and skip discovery. |
| `KEEP_OIDC_AUDIENCE` | — | Expected `aud`. When empty, `aud` is not verified. |
| `KEEP_OIDC_ALGORITHMS` | `RS256` | Comma-separated list of accepted signing algorithms. |
| `KEEP_OIDC_EMAIL_CLAIM` | `email` | Dotted claim path for the user identity. Falls back to `preferred_username`, then `sub`. |
| `KEEP_OIDC_TENANT_CLAIM` | `keep_tenant_id` | Dotted claim path for the tenant. Falls back to the single-tenant UUID. |

### Role resolution

| Variable | Default | Meaning |
| --- | --- | --- |
| `KEEP_OIDC_GROUPS_CLAIM` | `groups` | Dotted claim path to the user's groups. Keycloak realm roles live at `realm_access.roles`, client roles at `resource_access.<client-id>.roles`. Accepts a JSON array, a single string, or a comma-separated string. |
| `KEEP_OIDC_ROLE_CLAIM` | — | Dotted claim path to a Keep role name. When set and present, it wins over group mapping. |
| `KEEP_OIDC_ROLE_MAPPINGS` | — | Inline JSON, ordered by precedence: `[{"group": "keep-admins", "role": "admin"}, ...]`. The first mapping whose group is on the token wins. |
| `KEEP_OIDC_ROLE_MAPPINGS_FILE` | — | The same content as JSON or YAML in a file. Applied before the inline list. |
| `KEEP_OIDC_DEFAULT_ROLE` | — | Role for a user matching no mapping. Empty means deny (403). |

At least one of `KEEP_OIDC_ROLE_MAPPINGS`, `KEEP_OIDC_ROLE_CLAIM` or
`KEEP_OIDC_DEFAULT_ROLE` must be set, otherwise every token would be rejected
and the verifier refuses to start.

### Custom roles

| Variable | Default | Meaning |
| --- | --- | --- |
| `KEEP_CUSTOM_ROLES` | — | Inline JSON: `[{"name": "dba", "scopes": ["read:*"], "description": "..."}]`. |
| `KEEP_CUSTOM_ROLES_FILE` | — | The same content as JSON or YAML in a file (a bare list, or a mapping with a `roles` key). |
| `KEEP_CUSTOM_ROLES_STRICT` | `true` | `false` logs and continues with built-in roles only. That degrades **closed**: an unknown role gets a 403. |

Role names must match `^[a-z0-9][a-z0-9_-]*$`. Scopes are `{verb}:{resource}`,
where the resource may be `*`. The built-in roles `admin`, `noc`, `webhook` and
`workflowrunner` cannot be redefined.

### Resource permissions

| Variable | Default | Meaning |
| --- | --- | --- |
| `KEEP_RESOURCE_PERMISSIONS_FILE` | — | Path to a YAML or JSON file with the rules. |
| `KEEP_RESOURCE_PERMISSIONS` | — | The same content, inline JSON. Applied after the file. |
| `KEEP_RESOURCE_PERMISSIONS_MAX_SCAN` | `10000` | Upper bound on rows **returned** per rule. For incidents this bounds matched rows (the filtering happens in SQL); for presets it bounds fetched rows. Hitting it is logged as an error, and it hides data rather than exposing it. |

## Resource permission rules

A rule says "role R may see resources of type T whose attributes match M".

```yaml
rules:
  - role: dba
    resource_type: incident
    cel: "service in ['postgres', 'patroni']"
  - role: payments-oncall
    resource_type: preset
    match:
      name: [payments-*]
```

The file may be YAML or JSON, and may be either a bare list of rules or a
mapping with a `rules` key. Inline JSON uses the same shape.

### The selector language differs by resource type

| Resource type | Selector | Evaluated by |
| --- | --- | --- |
| `incident` | `cel:` | Keep's own CEL-to-SQL layer |
| `preset` | `match:` | this module, over fetched rows |

Using the wrong one is a configuration error, not a silently ignored key — an
incident rule carrying `match:` would otherwise become a rule with no
restriction at all, which fails in the permissive direction.

**Incidents use CEL** because Keep already ships a tested translator with a
provider per dialect (`keep/api/core/cel_to_sql/`). The attribute worth
restricting on, `affected_services`, is a JSON column, and JSON containment has
no portable spelling across SQLite, MySQL and PostgreSQL. Delegating means the
filtering happens in SQL rather than in Python, and it is the same language
already used in preset queries and the incident search bar.

**Presets use attribute matching** because Keep has no CEL query path over
presets, and they do not need one: `name` and `created_by` are scalar columns,
`tag` is a relationship, and a tenant has far fewer presets than incidents.

Any CEL expression valid in Keep's incident search is valid here, so a rule can
be developed by typing it into the incidents view and copying it once it selects
the right set.

Rules are **attribute-based, never object-based**. Nobody grants access to an
individual incident: the rule describes a property, and the matching resource
IDs are resolved at request time. An incident created a minute ago is covered by
an existing rule automatically.

### Supported resource types and match keys

Only `incident` and `preset` are supported, because they are the only resource
types Keep already enforces resource-level permissions on.

| Resource type | Match key | Matched against |
| --- | --- | --- |
| `incident` | `service` | membership in `affected_services` (a JSON list) |
| `incident` | `source` | membership in `sources` (a JSON list) |
| `incident` | `status` | `firing`, `resolved`, `acknowledged`, `merged`, `deleted` |
| `incident` | `severity` | either the name (`critical`) or the stored number (`5`) |
| `incident` | `assignee` | the assignee's email |
| `preset` | `name` | the preset name |
| `preset` | `tag` | membership in the preset's tags |
| `preset` | `created_by` | the creator's email |

### Matching semantics

For **incident** rules, semantics are CEL's own — the expression is passed to
Keep's query layer unchanged.

For **preset** rules:

* Values of one match key are **ORed**: `name: [a-*, b-*]` means either.
* Different keys inside one `match:` block are **ANDed**:
  `name: [a-*], created_by: [alice]` means both.
* Matching is **case-insensitive**.
* Values support simple glob patterns: `payments-*`, `db-?`, `[ab]-service`.
  A glob is not a substring match — `payments` does not match
  `payments-firing`, but `payments*` does. A literal value containing `*`, `?`
  or `[` is therefore interpreted as a pattern.
* A preset whose attribute is missing or empty never matches a rule on that
  attribute. A preset with no tags is not visible to a role restricted by
  `tag`, not even with `tag: ["*"]`.

For **both**, several rules for the same `(role, resource_type)` are **ORed**:
the allowed set is the union of what each rule resolves to. Incident rules are
unioned by running each expression separately rather than by joining them with
`||`, so one malformed expression fails on its own instead of quietly changing
what a different, correct rule selects.

### Fail-open semantics

Keep's call sites treat an empty ID list as "no limitations":

```python
# Note: if no limitations (allowed_preset_ids is []), then all presets are allowed
```

This connector preserves that contract:

* **No rules for a `(role, resource_type)`** → empty list → unrestricted. Roles
  with nothing configured, including all built-in roles, behave exactly as they
  did before this feature existed.
* **Rules present, some resources match** → exactly those IDs.
* **Rules present, nothing matches** → a single sentinel ID
  (`00000000-0000-0000-0000-000000000000`), **not** an empty list. An empty list
  would turn "matches nothing" into "sees everything".
* **An error while resolving** → the exception propagates and the request fails
  with a 500. Nothing in the resolution path converts a failure into an empty
  list, because that would silently grant access to everything.

> **A malformed rule set always aborts start-up, and there is no way to override
> that.** There is deliberately no counterpart to `KEEP_CUSTOM_ROLES_STRICT`.
> Dropping custom roles degrades closed — an unknown role gets a 403 and somebody
> notices immediately. Dropping restriction rules would degrade open: every role
> would silently see everything, with no failed request and a healthy-looking UI.
> An escape hatch reached for during an outage must not be the one that quietly
> removes an access control.
>
> Aborting is safe under a rolling deployment. The new pod never becomes ready,
> the running pods keep serving with the rule set they loaded at their own
> start-up, and the rollout stalls rather than degrading. Set
> `maxUnavailable: 0`, and alert on the Deployment's `Progressing=False`
> condition so a stalled rollout is reported rather than discovered. Catching a
> bad rule set before it reaches a cluster belongs in CI, which is not built yet.

### Where rules do and do not apply

Enforcement happens where Keep already asks the identity manager for permitted
resource IDs: incident listing, incident facets, incident reports, preset
listing and preset alerts. Alerts are not covered. Restricting incidents does
not restrict the alerts inside them, and a user who can reach an alert route can
still see alerts for services their incident rules exclude. Treat these rules as
scoping the incident and preset views, not as a data firewall.

A role restricted on presets also loses Keep's built-in static presets (the
`feed` preset), because the preset route only adds them when the role is
unrestricted. Add a matching rule if a restricted role needs them.

Rules are read once at start-up. Changing configuration requires a restart, and
the settings API is read-only: `POST /auth/permissions` returns 501 rather than
pretending to save.

## Worked example

Two teams share one Keep instance. The DBAs may only see incidents for the
database services; the payments on-call may only see their own presets.
Everybody else is unaffected.

**1. Define the roles.** Rules can only refer to roles that exist.

```bash
export KEEP_CUSTOM_ROLES='[
  {"name": "dba", "scopes": ["read:*"], "description": "database team"},
  {"name": "payments-oncall", "scopes": ["read:*"], "description": "payments on-call"}
]'
```

**2. Map provider groups onto them.** First match wins, so `keep-admins` is
listed first.

```bash
export KEEP_OIDC_ISSUER='https://sso.example.com/realms/keep'
export KEEP_OIDC_AUDIENCE='keep'
export KEEP_OIDC_GROUPS_CLAIM='realm_access.roles'
export KEEP_OIDC_ROLE_MAPPINGS='[
  {"group": "keep-admins", "role": "admin"},
  {"group": "dba", "role": "dba"},
  {"group": "payments-oncall", "role": "payments-oncall"},
  {"group": "engineering", "role": "noc"}
]'
```

**3. Restrict what those roles can see** — `/etc/keep/permissions.yaml`:

```yaml
rules:
  - role: dba
    resource_type: incident
    cel: "service in ['postgres', 'patroni', 'pgbouncer']"
  - role: dba
    resource_type: incident
    cel: "assignee == 'dba-oncall@example.com'"
  - role: payments-oncall
    resource_type: preset
    match:
      name: [payments-*]
```

```bash
export AUTH_TYPE=oidc
export KEEP_RESOURCE_PERMISSIONS_FILE=/etc/keep/permissions.yaml
```

**Result.**

* A user in the `dba` group sees an incident whose `affected_services` contains
  `postgres`, `patroni` or `pgbouncer`, **or** any incident assigned to
  `dba-oncall@example.com` (the two rules are ORed). An incident affecting only
  `billing` is not in their list and a direct request for it is refused. Their
  presets are unrestricted, because no preset rule names `dba`.
* A user in the `payments-oncall` group sees only presets whose name starts with
  `payments-`. `GET /preset/infra-overview/alerts` returns 403. Their incidents
  are unrestricted.
* An `admin` and a `noc` user see everything, exactly as before.
* If the DBAs' services are renamed and no incident matches any more, DBAs see
  an empty incident list — not the whole tenant.

## Performance

Roles without rules return before any query runs and cost nothing.

For **incidents**, filtering happens in SQL: the rule's CEL is handed to
`get_last_incidents_by_cel()` and the database returns only matching rows. The
cost is a query, and `KEEP_RESOURCE_PERMISSIONS_MAX_SCAN` bounds **matched**
rows rather than examined ones. A selective rule over a large tenant returns its
few hundred matches and never approaches the cap.

For **presets**, rows are fetched and filtered in memory. That is fine at preset
volumes and involves no JSON containment.

The cap exists at all because the upstream call sites take a **list of IDs**, so
the allowed set has to be enumerated rather than expressed as a predicate. If it
is reached, the rows beyond it are hidden from restricted roles and an error is
logged — that errs towards showing too little rather than too much, but it is
still wrong, so raise the cap or narrow the rule.

## Tests

* `tests/test_oidc_permissions.py` — rule parsing, validation and matching. No
  database required; also runnable directly with
  `python3 tests/test_oidc_permissions.py`.
* `tests/test_oidc_resource_resolver.py` — the database-backed half, using the
  `db_session` fixture from `tests/conftest.py`.
