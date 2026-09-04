"""Work item identity.

A work item is the unit an operator acts on - an Alertmanager group, or
whatever the source names with a dedup_key. An alert is a single fingerprinted
signal. `work_item_key` carries the first, `fingerprint` the second, and
deduplication sees only the second.
"""

import ast
import copy
import uuid
from datetime import datetime
from pathlib import Path

import pytest
import sqlmodel
from sqlalchemy.dialects import mysql, postgresql, sqlite

from keep.api.core.db import (
    get_correlation_deduplication_rule,
    get_custom_deduplication_rule,
    get_last_alerts_by_work_item_key,
)
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.alert import (
    AlertDto,
    AlertStatus,
    DeduplicationRuleType,
    normalize_work_item_key,
)
from keep.api.models.db.alert import Alert, AlertDeduplicationRule, LastAlert
from keep.api.tasks.process_event_task import process_event
from keep.providers.base.base_provider import BaseProvider
from keep.providers.prometheus_provider.prometheus_provider import PrometheusProvider
from tests.fixtures.client import client, setup_api_key, test_app  # noqa

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _alertmanager_payload(**overrides) -> dict:
    """A representative Alertmanager webhook body with two alerts in one group."""
    payload = {
        "receiver": "keep",
        "status": "firing",
        "externalURL": "http://alertmanager:9093",
        "version": "4",
        "groupKey": '{}:{alertname="HighCPU", cluster="eu-west"}',
        "groupLabels": {"alertname": "HighCPU", "cluster": "eu-west"},
        "commonLabels": {
            "alertname": "HighCPU",
            "cluster": "eu-west",
            "severity": "critical",
        },
        "commonAnnotations": {"summary": "cpu saturated"},
        "truncatedAlerts": 2,
        "alerts": [
            {
                "status": "firing",
                "fingerprint": "am-fp-node-1",
                "labels": {
                    "alertname": "HighCPU",
                    "cluster": "eu-west",
                    "instance": "node-1",
                    "severity": "critical",
                },
                "annotations": {"summary": "node-1 cpu saturated"},
            },
            {
                "status": "firing",
                "fingerprint": "am-fp-node-2",
                "labels": {
                    "alertname": "HighCPU",
                    "cluster": "eu-west",
                    "instance": "node-2",
                    "severity": "critical",
                },
                "annotations": {"summary": "node-2 cpu saturated"},
            },
        ],
    }
    payload.update(overrides)
    # _format_alert consumes the alert dicts it is handed, so every caller gets
    # its own copy
    return copy.deepcopy(payload)


def _add_rule(db_session, rule_type, fingerprint_fields, provider_type="keep"):
    rule = AlertDeduplicationRule(
        name=f"test {rule_type} rule",
        description=f"test {rule_type} rule",
        fingerprint_fields=fingerprint_fields,
        full_deduplication=False,
        ignore_fields=["lastReceived"],
        is_provisioned=False,
        tenant_id=SINGLE_TENANT_UUID,
        provider_id="test",
        provider_type=provider_type,
        created_by="test",
        last_updated_by="test",
        rule_type=DeduplicationRuleType(rule_type).value,
    )
    db_session.add(rule)
    db_session.commit()
    return rule


def _alert_dto(fingerprint, **kwargs):
    return AlertDto(
        id=str(uuid.uuid4()),
        name=kwargs.pop("name", "alert"),
        status=kwargs.pop("status", AlertStatus.FIRING),
        severity=kwargs.pop("severity", "critical"),
        lastReceived=datetime.utcnow().isoformat(),
        fingerprint=fingerprint,
        source=["keep"],
        **kwargs,
    )


def _process(event, provider_type="prometheus", fingerprint=None):
    return process_event(
        ctx={"job_try": 1},
        tenant_id=SINGLE_TENANT_UUID,
        provider_type=provider_type,
        provider_id="test",
        fingerprint=fingerprint,
        api_key_name="test",
        trace_id="test",
        event=event,
        notify_client=False,
    )


# ---------------------------------------------------------------------------
# The Alertmanager group survives ingestion
# ---------------------------------------------------------------------------


def test_group_envelope_is_preserved_on_every_member():
    alerts = PrometheusProvider._format_alert(_alertmanager_payload())

    assert len(alerts) == 2
    for alert in alerts:
        group = alert.alert_group
        assert group is not None
        assert group.key == '{}:{alertname="HighCPU", cluster="eu-west"}'
        assert group.labels == {"alertname": "HighCPU", "cluster": "eu-west"}
        assert group.common_labels["severity"] == "critical"
        assert group.common_annotations == {"summary": "cpu saturated"}
        assert group.receiver == "keep"
        assert group.external_url == "http://alertmanager:9093"
        assert group.size == 2
        assert group.truncated == 2


def test_group_members_share_a_work_item_but_keep_their_own_fingerprints():
    """One work item, N individually addressable alerts."""
    alerts = PrometheusProvider._format_alert(_alertmanager_payload())

    assert {a.fingerprint for a in alerts} == {"am-fp-node-1", "am-fp-node-2"}
    assert len({a.work_item_key for a in alerts}) == 1
    assert alerts[0].work_item_key != alerts[0].fingerprint


def test_group_key_is_used_verbatim():
    """The key stays matchable against the groupKey Alertmanager reports."""
    alerts = PrometheusProvider._format_alert(_alertmanager_payload())

    assert alerts[0].work_item_key == '{}:{alertname="HighCPU", cluster="eu-west"}'


def test_dedup_key_overrides_the_group_key():
    payload = _alertmanager_payload()
    payload["commonLabels"]["dedup_key"] = "WORK-42"

    alerts = PrometheusProvider._format_alert(payload)

    assert {a.work_item_key for a in alerts} == {"WORK-42"}


def test_alert_level_dedup_key_beats_the_group_level_one():
    payload = _alertmanager_payload()
    payload["commonLabels"]["dedup_key"] = "WORK-GROUP"
    payload["alerts"][0]["labels"]["dedup_key"] = "WORK-NODE-1"

    alerts = PrometheusProvider._format_alert(payload)

    assert [a.work_item_key for a in alerts] == ["WORK-NODE-1", "WORK-GROUP"]


def test_dedup_key_is_read_from_annotations_and_case_insensitively():
    payload = _alertmanager_payload()
    payload["commonAnnotations"]["Dedup_Key"] = "WORK-ANN"

    alerts = PrometheusProvider._format_alert(payload)

    assert {a.work_item_key for a in alerts} == {"WORK-ANN"}


def test_payload_without_grouping_gets_no_work_item():
    alerts = PrometheusProvider._format_alert(
        {"status": "firing", "labels": {"alertname": "HighCPU"}, "annotations": {}}
    )

    assert alerts[0].alert_group is None
    assert alerts[0].work_item_key is None


def test_bare_alerts_list_is_not_treated_as_a_group():
    alerts = PrometheusProvider._format_alert(
        {"alerts": [{"status": "firing", "labels": {"alertname": "X"}}]}
    )

    assert alerts[0].alert_group is None
    assert alerts[0].work_item_key is None


def test_overlong_work_item_key_is_digested_not_truncated():
    """Two long keys sharing a 255 character prefix must stay distinct."""
    a = normalize_work_item_key("x" * 300 + "-a")
    b = normalize_work_item_key("x" * 300 + "-b")

    assert len(a) == 64 and len(b) == 64
    assert a != b
    assert normalize_work_item_key("short") == "short"
    assert normalize_work_item_key("") is None


# ---------------------------------------------------------------------------
# Work item key computation from a correlate rule
# ---------------------------------------------------------------------------


def test_single_field_correlate_rule_passes_the_value_through():
    alert = _alert_dto("fp", labels={"dedup_key": "WORK-7"})

    assert BaseProvider.get_work_item_key(alert, ["labels.dedup_key"]) == "WORK-7"


def test_multi_field_correlate_rule_hashes():
    """A concatenation of fields means nothing outside Keep, so it is hashed."""
    alert = _alert_dto("fp", labels={"service": "payments", "cluster": "eu"})

    key = BaseProvider.get_work_item_key(
        alert, ["labels.service", "labels.cluster"]
    )

    assert len(key) == 64
    assert key != "paymentseu"


def test_correlate_rule_that_does_not_apply_returns_none():
    """None means "this rule has nothing to say", not "the key is empty"."""
    alert = _alert_dto("fp", labels={"service": "payments"})

    assert BaseProvider.get_work_item_key(alert, ["labels.absent"]) is None
    assert BaseProvider.get_work_item_key(alert, []) is None


def test_correlate_rule_overrides_the_key_derived_from_the_payload(db_session):
    """An operator's rule is more specific than a groupKey heuristic."""
    _add_rule(db_session, "correlate", ["labels.instance"], provider_type="prometheus")

    alerts = PrometheusProvider.format_alert(
        event=_alertmanager_payload(),
        tenant_id=SINGLE_TENANT_UUID,
        provider_id="test",
        provider_type="prometheus",
    )

    assert [a.work_item_key for a in alerts] == ["node-1", "node-2"]


def test_correlate_rule_key_is_normalized(db_session):
    """A rule can point at a field longer than the column."""
    _add_rule(db_session, "correlate", ["labels.long"], provider_type="prometheus")
    payload = _alertmanager_payload()
    for alert in payload["alerts"]:
        alert["labels"]["long"] = "x" * 300

    alerts = PrometheusProvider.format_alert(
        event=payload,
        tenant_id=SINGLE_TENANT_UUID,
        provider_id="test",
        provider_type="prometheus",
    )

    assert {len(a.work_item_key) for a in alerts} == {64}


def test_correlate_rule_leaves_the_fingerprint_alone(db_session):
    _add_rule(db_session, "correlate", ["labels.alertname"], provider_type="prometheus")

    alerts = PrometheusProvider.format_alert(
        event=_alertmanager_payload(),
        tenant_id=SINGLE_TENANT_UUID,
        provider_id="test",
        provider_type="prometheus",
    )

    assert [a.fingerprint for a in alerts] == ["am-fp-node-1", "am-fp-node-2"]
    assert {a.work_item_key for a in alerts} == {"HighCPU"}


def test_split_and_correlate_rules_coexist_on_one_provider(db_session):
    _add_rule(db_session, "split", ["labels.instance"], provider_type="prometheus")
    _add_rule(db_session, "correlate", ["labels.alertname"], provider_type="prometheus")

    assert (
        get_custom_deduplication_rule(SINGLE_TENANT_UUID, "test", "prometheus").rule_type
        == "split"
    )
    assert (
        get_correlation_deduplication_rule(
            SINGLE_TENANT_UUID, "test", "prometheus"
        ).rule_type
        == "correlate"
    )

    alerts = PrometheusProvider.format_alert(
        event=_alertmanager_payload(),
        tenant_id=SINGLE_TENANT_UUID,
        provider_id="test",
        provider_type="prometheus",
    )

    # the split rule decides the fingerprint, the correlate rule the work item,
    # and neither reaches into the other
    assert len({a.fingerprint for a in alerts}) == 2
    assert "am-fp-node-1" not in {a.fingerprint for a in alerts}
    assert {a.work_item_key for a in alerts} == {"HighCPU"}


def test_correlate_rule_is_applied_to_pulled_alerts(db_session, mocker):
    """The pull path has to agree with the webhook path."""
    _add_rule(db_session, "correlate", ["labels.dedup_key"], provider_type="prometheus")

    provider = PrometheusProvider.__new__(PrometheusProvider)
    provider.provider_id = "test"
    provider.provider_type = "prometheus"
    provider.context_manager = mocker.Mock(tenant_id=SINGLE_TENANT_UUID)
    mocker.patch.object(
        PrometheusProvider,
        "_get_alerts",
        return_value=[_alert_dto("fp-pulled", labels={"dedup_key": "WORK-PULL"})],
    )

    alerts = provider.get_alerts()

    assert alerts[0].work_item_key == "WORK-PULL"
    assert alerts[0].fingerprint == "fp-pulled"


# ---------------------------------------------------------------------------
# Persistence and querying
# ---------------------------------------------------------------------------


def test_work_item_key_is_persisted_and_queryable(db_session):
    _process(_alertmanager_payload())

    alerts = db_session.query(Alert).all()
    assert len(alerts) == 2
    assert {a.event["work_item_key"] for a in alerts} == {
        '{}:{alertname="HighCPU", cluster="eu-west"}'
    }

    members = get_last_alerts_by_work_item_key(
        SINGLE_TENANT_UUID, '{}:{alertname="HighCPU", cluster="eu-west"}'
    )
    assert {m.fingerprint for m in members} == {"am-fp-node-1", "am-fp-node-2"}


def test_the_group_envelope_reaches_the_database(db_session):
    _process(_alertmanager_payload())

    alert = db_session.query(Alert).first()
    assert alert.event["alert_group"]["size"] == 2
    assert alert.event["alert_group"]["labels"]["cluster"] == "eu-west"


def test_alerts_of_one_group_stay_separate_rows(db_session):
    _process(_alertmanager_payload())

    assert db_session.query(Alert).count() == 2
    assert db_session.query(LastAlert).count() == 2
    assert (
        len(
            get_last_alerts_by_work_item_key(
                SINGLE_TENANT_UUID, '{}:{alertname="HighCPU", cluster="eu-west"}'
            )
        )
        == 2
    )


def test_alerts_without_a_work_item_store_null(db_session):
    _process(
        {"status": "firing", "labels": {"alertname": "Solo"}, "annotations": {}},
    )

    last_alert = db_session.query(LastAlert).one()
    assert last_alert.work_item_key is None


def test_work_item_key_follows_the_latest_occurrence(db_session):
    """Regrouping at the source moves the alert to the new work item."""
    _process(_alertmanager_payload())

    moved = _alertmanager_payload()
    moved["commonLabels"]["dedup_key"] = "WORK-MOVED"
    _process(moved)

    assert {la.work_item_key for la in db_session.query(LastAlert).all()} == {
        "WORK-MOVED"
    }


# ---------------------------------------------------------------------------
# Deduplication must not notice any of this
# ---------------------------------------------------------------------------


def test_work_item_metadata_does_not_change_the_alert_hash(db_session):
    """A correlate rule leaves the deduplication hash of every alert alone."""
    _process(_alertmanager_payload())
    hashes_without_rule = {
        la.fingerprint: la.alert_hash for la in db_session.query(LastAlert).all()
    }

    _add_rule(db_session, "correlate", ["labels.alertname"], provider_type="prometheus")
    _process(_alertmanager_payload())

    hashes_with_rule = {
        la.fingerprint: la.alert_hash for la in db_session.query(LastAlert).all()
    }
    assert hashes_with_rule == hashes_without_rule
    # and the repeat is still a full duplicate
    assert db_session.query(Alert).count() == 2


def test_repeated_group_is_deduplicated(db_session):
    _process(_alertmanager_payload())
    _process(_alertmanager_payload())

    assert db_session.query(Alert).count() == 2


# ---------------------------------------------------------------------------
# Rule management
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("test_app", [{"AUTH_TYPE": "NOAUTH"}], indirect=True)
def test_rule_type_round_trips_through_the_api(db_session, client, test_app):
    _process(_alertmanager_payload())  # registers the linked provider

    response = client.post(
        "/deduplications",
        json={
            "name": "work items by dedup_key",
            "description": "correlate",
            "provider_type": "prometheus",
            "provider_id": "test",
            "fingerprint_fields": ["labels.dedup_key"],
            "full_deduplication": False,
            "ignore_fields": None,
            "rule_type": "correlate",
        },
        headers={"x-api-key": "some-api-key"},
    )
    assert response.status_code == 200
    assert response.json()["rule_type"] == "correlate"

    rules = client.get("/deduplications", headers={"x-api-key": "some-api-key"}).json()
    created = [r for r in rules if r["name"] == "work items by dedup_key"]
    assert len(created) == 1
    assert created[0]["rule_type"] == "correlate"


@pytest.mark.parametrize("test_app", [{"AUTH_TYPE": "NOAUTH"}], indirect=True)
def test_a_second_rule_of_the_same_type_is_refused(db_session, client, test_app):
    _process(_alertmanager_payload())

    body = {
        "name": "first",
        "description": "correlate",
        "provider_type": "prometheus",
        "provider_id": "test",
        "fingerprint_fields": ["labels.dedup_key"],
        "full_deduplication": False,
        "ignore_fields": None,
        "rule_type": "correlate",
    }
    assert (
        client.post(
            "/deduplications", json=body, headers={"x-api-key": "some-api-key"}
        ).status_code
        == 200
    )

    duplicate = client.post(
        "/deduplications",
        json={**body, "name": "second"},
        headers={"x-api-key": "some-api-key"},
    )
    assert duplicate.status_code == 409

    # ... while the other type is still free
    assert (
        client.post(
            "/deduplications",
            json={**body, "name": "split one", "rule_type": "split"},
            headers={"x-api-key": "some-api-key"},
        ).status_code
        == 200
    )


@pytest.mark.parametrize("test_app", [{"AUTH_TYPE": "NOAUTH"}], indirect=True)
def test_an_unknown_rule_type_is_rejected(db_session, client, test_app):
    """A typo would create a rule invisible to both getters."""
    _process(_alertmanager_payload())

    response = client.post(
        "/deduplications",
        json={
            "name": "typo",
            "description": "typo",
            "provider_type": "prometheus",
            "provider_id": "test",
            "fingerprint_fields": ["labels.dedup_key"],
            "full_deduplication": False,
            "ignore_fields": None,
            "rule_type": "corelate",
        },
        headers={"x-api-key": "some-api-key"},
    )
    assert response.status_code == 422


def test_rules_default_to_split(db_session):
    """A rule stored without a type computes the fingerprint."""
    rule = AlertDeduplicationRule(
        name="untyped",
        description="a rule stored without a rule_type",
        fingerprint_fields=["fingerprint"],
        full_deduplication=False,
        ignore_fields=[],
        is_provisioned=False,
        tenant_id=SINGLE_TENANT_UUID,
        provider_id="test",
        provider_type="prometheus",
        created_by="test",
        last_updated_by="test",
    )
    db_session.add(rule)
    db_session.commit()

    assert rule.rule_type == "split"
    assert (
        get_custom_deduplication_rule(SINGLE_TENANT_UUID, "test", "prometheus").id
        == rule.id
    )
    assert (
        get_correlation_deduplication_rule(SINGLE_TENANT_UUID, "test", "prometheus")
        is None
    )


# ---------------------------------------------------------------------------
# Schema
#
# The suite builds its schema with SQLModel.metadata.create_all and never runs
# alembic, so the migration needs coverage of its own. These compile the column
# types against every supported dialect, without a live server.
# ---------------------------------------------------------------------------

MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "keep/api/models/db/migrations/versions/2026-09-04-10-00_work_item_identity.py"
)


@pytest.mark.parametrize(
    "dialect,expected",
    [(mysql.dialect(), "VARCHAR(255)"), (postgresql.dialect(), "VARCHAR"), (sqlite.dialect(), "VARCHAR")],
)
def test_new_columns_compile_on_every_supported_database(dialect, expected):
    for column in (
        LastAlert.__table__.columns["work_item_key"],
        AlertDeduplicationRule.__table__.columns["rule_type"],
    ):
        assert column.type.compile(dialect=dialect) == expected


def test_migration_uses_the_same_type_as_the_models():
    tree = ast.parse(MIGRATION.read_text())
    column_types = [
        node.func
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    rendered = {ast.unparse(func) for func in column_types}

    # sa.String() carries no length and raises CompileError on MySQL
    assert "sa.String" not in rendered
    assert "sqlmodel.sql.sqltypes.AutoString" in rendered
    assert (
        sqlmodel.sql.sqltypes.AutoString().compile(dialect=mysql.dialect())
        == "VARCHAR(255)"
    )
