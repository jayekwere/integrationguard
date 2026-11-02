from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from app.common import (
    Contract,
    DomainError,
    Identity,
    Ref,
    VersionRef,
    digest,
    fresh,
    get,
    put,
    require,
    versioned,
)


class Integration(Ref):
    provider: Literal["salesforce-export", "synthetic-gateway"]
    owner: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    scopes: list[str] = Field(max_length=20)
    modify_all_data: bool | None
    mfa_required: bool | None
    observed_at: str = Field(min_length=20, max_length=40)
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_ref: str = Field(min_length=1, max_length=200)


class Correct(VersionRef):
    scopes: list[str] = Field(max_length=20)
    modify_all_data: bool | None
    mfa_required: bool | None
    observed_at: str = Field(min_length=20, max_length=40)
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class Event(Ref):
    integration_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    event: Literal["login-failure", "bulk-export", "configuration-change"]
    occurred_at: str = Field(min_length=20, max_length=40)
    native_id: str = Field(min_length=1, max_length=80)


MODELS: dict[str, type[Contract]] = {
    "import-integration": Integration,
    "record-correction": Correct,
    "ingest-event": Event,
}


def findings(item: dict[str, Any], now: str) -> list[dict[str, str]]:
    result = []
    if not fresh(item["observed_at"], now, 24):
        result.append(
            {
                "rule": "IG000",
                "pointer": "/observed_at",
                "state": "stale",
                "recommendation": "Collect a fresh read-only export",
            }
        )
    if any(scope in {"full", "api:write", "*"} for scope in item["scopes"]):
        result.append(
            {
                "rule": "IG001",
                "pointer": "/scopes",
                "state": "observed-excess",
                "recommendation": "Review and narrow the explicit integration scope",
            }
        )
    for key, rule in [("modify_all_data", "IG002"), ("mfa_required", "IG003")]:
        value = item[key]
        if value is None or value == (key == "modify_all_data"):
            result.append(
                {
                    "rule": rule,
                    "pointer": f"/{key}",
                    "state": "missing" if value is None else "observed-risk",
                    "recommendation": "Review this setting in the source system and collect replacement evidence",
                }
            )
    return result


def dispatch(
    state: dict[str, Any], actor: Identity, action: str, value: Contract, now: str
) -> dict[str, Any]:
    data = value.model_dump()
    require(actor, "operator")
    if action == "import-integration":
        if not fresh(data["observed_at"], now, 24 * 90) or len(set(data["scopes"])) != len(
            data["scopes"]
        ):
            raise DomainError("Observation date or duplicate scopes invalid", 422)
        record = {
            **data,
            "version": 1,
            "source_trust": "operator_imported_export",
            "previous_sha256": None,
        }
        record["findings"] = findings(record, now)
        record["sha256"] = digest(record)
        put(state, "snapshot", record["sha256"], record, create=True)
        return put(state, "integration", data["id"], record, create=True)
    item = get(state, "integration", data.get("integration_id", data["id"]))
    if action == "record-correction":
        versioned(item, data["version"])
        if not fresh(data["observed_at"], now, 24) or len(set(data["scopes"])) != len(
            data["scopes"]
        ):
            raise DomainError("Correction evidence must be fresh", 422)
        updated = {
            **item,
            **data,
            "version": item["version"] + 1,
            "previous_sha256": item["sha256"],
        }
        updated.pop("sha256", None)
        updated["findings"] = findings(updated, now)
        updated["sha256"] = digest(updated)
        put(state, "snapshot", updated["sha256"], updated, create=True)
        return put(state, "integration", data["id"], updated)
    if not fresh(data["occurred_at"], now, 24):
        raise DomainError("Security event is stale or future-dated", 422)
    for existing in state.get("event", {}).values():
        if (
            existing["integration_id"] == data["integration_id"]
            and existing["native_id"] == data["native_id"]
        ):
            if existing["event"] != data["event"] or existing["occurred_at"] != data["occurred_at"]:
                raise DomainError("Native event id conflicts with existing event")
            return dict(existing)
    return put(
        state,
        "event",
        data["id"],
        {
            **data,
            "severity": "high" if data["event"] == "bulk-export" else "medium",
            "format": "integrationguard-event-v1",
            "evidence_sha256": item["sha256"],
        },
        create=True,
    )


def view(state: dict[str, Any], actor: Identity, now: str) -> dict[str, Any]:
    if not set(actor.roles) & {"operator", "reviewer", "auditor"}:
        raise DomainError("Role not authorized", 403)
    return {
        "integrations": [
            {**item, "findings": findings(item, now)}
            for item in state.get("integration", {}).values()
        ],
        "events": list(state.get("event", {}).values()),
        "native_effective_permissions": "not_proven",
        "corrections": "evidence_import_only_no_provider_writes",
    }
