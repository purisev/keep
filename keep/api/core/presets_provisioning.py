"""
Declarative provisioning of presets.

A preset in Keep is a saved query: a name plus a CEL expression. That makes it
the natural unit for a per-team alert feed — give a team a preset scoped to its
services, grant its role access to that preset through the OIDC resource
permission rules, and the team gets a feed containing only its own alerts.

Upstream Keep provisions providers, workflows, dashboards, deduplication rules
and mapping rules from configuration, but not presets, so a per-team feed could
not be described in Git. This module closes that gap, following the same shape
as keep/api/alert_deduplicator/deduplication_rules_provisioning.py.

Configuration:

    KEEP_PRESETS_FILE   path to a YAML or JSON file
    KEEP_PRESETS        the same content, inline JSON

Schema:

    presets:
      - name: dba-feed
        cel: "service in ['postgres', 'patroni']"
        tags: [dba]
        is_private: false
        is_noisy: false
        counter_shows_firing_only: false
        created_by: provisioning

Reconciliation is full: a preset removed from the configuration is deleted from
the database on the next start. **Only rows with is_provisioned=True are ever
deleted** — a preset somebody created in the UI is never touched, even if its
name disappears from the file, because it was never in the file to begin with.

A malformed configuration aborts start-up, for the same reason the resource
permission rules do: with a rolling deployment the previous pods keep serving
and the rollout stalls, which is strictly better than a half-applied state.
"""

import json
import logging
import os

# The database stack is imported inside the functions that reconcile, not at
# module scope, so the parsing and validation half of this module stays
# importable without it. That is what lets the configuration be checked by a CI
# job that has no database -- the primary defence against a bad file reaching a
# cluster -- and it keeps the validation rules unit-testable.

logger = logging.getLogger(__name__)

# The name of Keep's built-in static preset. It is a constant in
# keep/api/consts.py rather than a row, so a provisioned preset using the same
# name would be shadowed by it at keep/api/routes/preset.py and never resolve.
STATIC_PRESET_NAMES = ("feed",)

DEFAULT_CREATED_BY = "provisioning"

# Marks the origin of a provisioned row, mirroring Workflow.provisioned_file.
# A single file (or inline JSON) is the whole configuration here, so this is
# informational rather than a reconciliation key.
INLINE_SOURCE = "<KEEP_PRESETS>"


class PresetProvisioningError(Exception):
    """Raised when KEEP_PRESETS / KEEP_PRESETS_FILE cannot be applied."""


def _read_definitions() -> tuple[list, str | None]:
    """
    Read preset definitions and the source they came from.

    Returns (definitions, source). `source` is None when nothing is configured,
    which is what distinguishes "provisioning disabled" from "provision an empty
    set" -- the second one would delete every provisioned preset.
    """
    path = os.environ.get("KEEP_PRESETS_FILE", "").strip()
    inline = os.environ.get("KEEP_PRESETS", "").strip()

    if not path and not inline:
        return [], None

    definitions: list = []
    source_parts: list[str] = []

    if path:
        try:
            import yaml

            with open(path, "r", encoding="utf-8") as handle:
                parsed = yaml.safe_load(handle) or []
        except OSError as exc:
            raise PresetProvisioningError(
                f"Cannot read KEEP_PRESETS_FILE {path!r}: {exc}"
            ) from exc
        except Exception as exc:
            raise PresetProvisioningError(
                f"Cannot parse KEEP_PRESETS_FILE {path!r}: {exc}"
            ) from exc
        if isinstance(parsed, dict):
            parsed = parsed.get("presets", [])
        if not isinstance(parsed, list):
            raise PresetProvisioningError(
                f"KEEP_PRESETS_FILE {path!r} must contain a list of presets"
            )
        definitions.extend(parsed)
        source_parts.append(path)

    if inline:
        try:
            parsed = json.loads(inline)
        except ValueError as exc:
            raise PresetProvisioningError(
                f"Cannot parse KEEP_PRESETS as JSON: {exc}"
            ) from exc
        if isinstance(parsed, dict):
            parsed = parsed.get("presets", [])
        if not isinstance(parsed, list):
            raise PresetProvisioningError("KEEP_PRESETS must be a list of presets")
        definitions.extend(parsed)
        source_parts.append(INLINE_SOURCE)

    return definitions, ",".join(source_parts)


def _validate(definition) -> dict:
    """Normalise one preset definition, raising on anything malformed."""
    if not isinstance(definition, dict):
        raise PresetProvisioningError(
            f"Preset definition must be a mapping, got {definition!r}"
        )

    name = definition.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PresetProvisioningError(f"Preset needs a non-empty name: {definition!r}")
    name = name.strip()
    if name in STATIC_PRESET_NAMES:
        raise PresetProvisioningError(
            f"Preset name {name!r} collides with Keep's built-in static preset, "
            "which would shadow it and make it unreachable"
        )

    cel = definition.get("cel")
    if not isinstance(cel, str):
        raise PresetProvisioningError(
            f"Preset {name!r} needs a 'cel' string (use \"\" for an unfiltered feed)"
        )

    tags = definition.get("tags", []) or []
    if not isinstance(tags, list) or any(
        not isinstance(tag, str) or not tag.strip() for tag in tags
    ):
        raise PresetProvisioningError(
            f"Preset {name!r} has invalid tags {tags!r}: expected a list of strings"
        )

    for flag in ("is_private", "is_noisy", "counter_shows_firing_only"):
        if flag in definition and not isinstance(definition[flag], bool):
            raise PresetProvisioningError(
                f"Preset {name!r} field {flag!r} must be a boolean"
            )

    return {
        "name": name,
        "cel": cel,
        "tags": [tag.strip() for tag in tags],
        "is_private": bool(definition.get("is_private", False)),
        "is_noisy": bool(definition.get("is_noisy", False)),
        "counter_shows_firing_only": bool(
            definition.get("counter_shows_firing_only", False)
        ),
        "created_by": definition.get("created_by") or DEFAULT_CREATED_BY,
    }


def _options_for(cel: str) -> list:
    """
    Build the `options` payload a preset stores its query in.

    PresetDto.cel_query and .sql_query pick their entry out of this list by
    label, so both must be present even when the SQL half is unused.
    """
    return [
        {"label": "CEL", "value": cel},
        {"label": "SQL", "value": {"sql": "", "params": {}}},
    ]


def _sync_tags(session, tenant_id: str, preset, tag_names: list[str]):
    """Attach exactly `tag_names` to `preset`, creating Tag rows as needed."""
    from sqlmodel import select

    from keep.api.models.db.preset import PresetTagLink, Tag

    existing_links = session.exec(
        select(PresetTagLink).where(
            PresetTagLink.tenant_id == tenant_id,
            PresetTagLink.preset_id == preset.id,
        )
    ).all()
    for link in existing_links:
        session.delete(link)

    for tag_name in tag_names:
        tag = session.exec(
            select(Tag).where(Tag.tenant_id == tenant_id, Tag.name == tag_name)
        ).first()
        if tag is None:
            tag = Tag(tenant_id=tenant_id, name=tag_name)
            session.add(tag)
            session.flush()
        session.add(
            PresetTagLink(tenant_id=tenant_id, preset_id=preset.id, tag_id=tag.id)
        )


def provision_presets_from_env(tenant_id: str) -> None:
    """
    Reconcile the tenant's provisioned presets with the configuration.

    Does nothing at all when neither KEEP_PRESETS nor KEEP_PRESETS_FILE is set:
    an unconfigured deployment must not have its provisioned presets deleted
    just because the variables are absent.
    """
    definitions, source = _read_definitions()
    if source is None:
        logger.info("No presets configured. Nothing to provision.")
        return

    desired = [_validate(definition) for definition in definitions]

    names = [preset["name"] for preset in desired]
    duplicates = {name for name in names if names.count(name) > 1}
    if duplicates:
        raise PresetProvisioningError(
            f"Duplicate preset names in configuration: {sorted(duplicates)}"
        )
    desired_by_name = {preset["name"]: preset for preset in desired}

    from sqlmodel import Session, select

    from keep.api.core import db as core_db
    from keep.api.models.db.preset import Preset, PresetTagLink

    with Session(core_db.engine) as session:
        existing = session.exec(
            select(Preset).where(Preset.tenant_id == tenant_id)
        ).unique().all()
        existing_by_name = {preset.name: preset for preset in existing}

        # Refuse to adopt a preset a human owns. Taking it over would mean the
        # next configuration change deletes somebody's work as if we had made it.
        for name in desired_by_name:
            current = existing_by_name.get(name)
            if current is not None and not current.is_provisioned:
                raise PresetProvisioningError(
                    f"Preset {name!r} already exists and was not provisioned. "
                    "Rename the configured preset, or delete the existing one "
                    "first if it is meant to be managed from configuration."
                )

        for name, spec in desired_by_name.items():
            preset = existing_by_name.get(name)
            if preset is None:
                preset = Preset(
                    tenant_id=tenant_id,
                    name=name,
                    created_by=spec["created_by"],
                    options=_options_for(spec["cel"]),
                )
                session.add(preset)
                session.flush()
                logger.info("Provisioned new preset %s", name)
            else:
                preset.options = _options_for(spec["cel"])
                preset.created_by = spec["created_by"]
                logger.info("Updated provisioned preset %s", name)

            preset.is_private = spec["is_private"]
            preset.is_noisy = spec["is_noisy"]
            preset.counter_shows_firing_only = spec["counter_shows_firing_only"]
            preset.is_provisioned = True
            preset.provisioned_file = source
            session.add(preset)
            _sync_tags(session, tenant_id, preset, spec["tags"])

        # Full reconciliation, scoped to rows we own.
        for preset in existing:
            if preset.is_provisioned and preset.name not in desired_by_name:
                logger.info(
                    "Deleting provisioned preset %s: no longer in configuration",
                    preset.name,
                )
                for link in session.exec(
                    select(PresetTagLink).where(
                        PresetTagLink.tenant_id == tenant_id,
                        PresetTagLink.preset_id == preset.id,
                    )
                ).all():
                    session.delete(link)
                session.delete(preset)

        session.commit()

    logger.info("Provisioned %s presets for tenant %s", len(desired), tenant_id)
