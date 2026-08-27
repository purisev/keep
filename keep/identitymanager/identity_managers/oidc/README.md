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
| `oidc_permission_cache.py` | Process-local TTL cache for resolved allowed-ID sets |
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
| `KEEP_OIDC_ROLE_COMPOSITION` | `first-match` | `first-match`: the first mapping whose group is on the token wins — list order is the precedence. `union`: every matching mapping contributes; two or more distinct roles become a composite (see below). |

At least one of `KEEP_OIDC_ROLE_MAPPINGS`, `KEEP_OIDC_ROLE_CLAIM` or
`KEEP_OIDC_DEFAULT_ROLE` must be set, otherwise every token would be rejected
and the verifier refuses to start.

### Role composition (`KEEP_OIDC_ROLE_COMPOSITION=union`)

A user whose groups map to several roles gets a composite role assembled at
token verification — nothing to configure per combination:

* The composite's name is the sorted member names joined with `+`
  (`team-data+team-ml`). `+` is rejected by the role-name pattern, so an
  operator-defined role can never collide with a composite.
* **Scopes** are the union of the members' scopes.
* **Resource permissions** expand to the members with *unrestricted-wins*
  semantics: if any member has no rules for a resource type, that member alone
  would see everything, so the composite does too — belonging to two teams can
  never grant less than belonging to one. When every member is restricted, the
  members' rules are unioned like any other multi-rule set.
* A member with a deny-all rule contributes nothing but does not veto the
  others.
* `KEEP_OIDC_ROLE_CLAIM`, when set and present, still wins as a single role;
  `KEEP_OIDC_DEFAULT_ROLE` still applies only when no mapping matched.
* The users list shows the composite name — it is self-describing.

The default stays `first-match` because unioning silently *broadens* access
for multi-group users; switching an existing deployment to `union` is an
access-model decision, not a cosmetic one.

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
| `KEEP_RESOURCE_PERMISSIONS_CACHE_TTL` | `15` | Seconds a resolved allowed-ID set is reused. `0` disables the cache. See [Caching](#caching). |

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

Enforcement happens in two layers.

Where Keep already asks the identity manager for permitted resource IDs:
incident listing, incident facets, incident reports, preset listing and preset
alerts. The id-addressed incident routes (get, update, delete, split, merge,
alerts, workflows, assign, status, severity, comment, confirm, enrich,
unenrich) additionally refuse with 403 any incident id outside the caller's
resolved scope — a restricted role can no longer read or mutate an incident
by knowing its id.

And on the alert routes, which never consulted the identity manager at all: a
role restricted on **presets** is also restricted to the union of its allowed
presets' CEL on every alert-returning or alert-addressed route — the alert
query and its facets (including per-facet queries, which are parenthesized so
a top-level `||` cannot escape the scope), the plain alert list, search,
fetching by fingerprint batch, and the fingerprint-addressed routes (history,
audit, assign, enrich, unenrich, delete), which return 403 for an alert
outside the scope — an unknown fingerprint included, since it cannot be shown
to be in scope and the enrichment routes would otherwise create state for it.
Error alerts (`/alerts/event/error`) and the per-provider quality metrics are
tenant-wide data no preset CEL can classify, so a restricted role gets none of
them. Where the route goes through the CEL-to-SQL layer the scope is ANDed
into the query; elsewhere it is applied in memory with the same RulesEngine
CEL evaluation presets themselves use, so an alert is visible through a side
route exactly when it shows up in an allowed preset.

Restricting **incidents** does not restrict the alerts inside them — alert
visibility follows preset rules, incident visibility follows incident rules.
Give a team both kinds of rule.

The websocket channel only carries "poll" signals (fingerprint lists and
preset names, capped), never alert payloads; clients re-fetch through the
scoped query route. Fingerprints and preset names are visible to every
authenticated member of the tenant.

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

## Caching

Resolution runs on every request to a protected route, and the UI polls: the
alerts table and the incident list refetch every ~6 seconds, the preset counters
every 5. The answer depends on the tenant, the role and the resource type and on
nothing that varies per request, so it is cached under exactly that key — every
user holding the same role shares one entry.

`KEEP_RESOURCE_PERMISSIONS_CACHE_TTL` (default 15 s) bounds how stale that entry
may be. It is deliberately longer than the UI's poll interval: a TTL below ~6 s
would miss on nearly every poll from a single tab and save nothing.

**The TTL is the only guarantee.** The cache lives in the worker process, and
the API runs four of them, so:

* a new incident becomes visible to a restricted role within the TTL, not
  immediately — incidents are created by the alert pipeline, in ARQ workers that
  share nothing with the API workers;
* creating, updating or deleting a preset drops the cached preset entry, but
  only in the worker that served the write. The other workers wait out the TTL.

Set the TTL to `0` if a deployment cannot accept that; resolution then runs per
request as before.

Two things are deliberately **not** cached:

* the token → `AuthenticatedEntity` validation, because an entry outliving the
  token's `exp` would keep an expired token working;
* a failed resolution. The contract is fail-open — an empty list means
  "unrestricted" — so a cached database error would grant access to everything.
  Errors propagate and nothing is stored.

Signing keys are cached separately, by PyJWT itself: the verifier constructs
`PyJWKClient(..., cache_keys=True)` so the JWKS keys are parsed once rather than
rebuilt from JSON on every request.

## Tests

* `tests/test_oidc_permissions.py` — rule parsing, validation and matching. No
  database required; also runnable directly with
  `python3 tests/test_oidc_permissions.py`.
* `tests/test_oidc_resource_resolver.py` — the database-backed half, using the
  `db_session` fixture from `tests/conftest.py`.
