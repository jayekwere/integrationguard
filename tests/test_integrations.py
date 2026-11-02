from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.common import DEMO_IDENTITIES, DomainError, Store
from app.domain import Correct, Event, Integration, dispatch, findings, view
from app.gateway import Gateway, GatewayRequest, backend
from app.salesforce import collect

NOW = "2026-11-01T12:00:00Z"
OP = DEMO_IDENTITIES["demo-operator"]


def seed() -> dict[str, Any]:
    state: dict[str, Any] = {}
    dispatch(
        state,
        OP,
        "import-integration",
        Integration(
            id="gateway",
            provider="synthetic-gateway",
            owner="platform",
            scopes=["synthetic:read"],
            modify_all_data=False,
            mfa_required=True,
            observed_at=NOW,
            source_sha256="a" * 64,
            source_ref="fixture",
        ),
        NOW,
    )
    return state


def test_missing_stale_and_conflicting_events() -> None:
    state = seed()
    item = state["integration"]["gateway"]
    assert findings(item, NOW) == []
    assert findings(item, "2026-11-03T12:00:00Z")[0]["state"] == "stale"
    bad = Integration(
        id="bad",
        provider="salesforce-export",
        owner="platform",
        scopes=["full", "full"],
        modify_all_data=True,
        mfa_required=None,
        observed_at=NOW,
        source_sha256="a" * 64,
        source_ref="fixture",
    )
    with pytest.raises(DomainError):
        dispatch(state, OP, "import-integration", bad, NOW)
    event = Event(
        id="event",
        integration_id="gateway",
        event="login-failure",
        occurred_at=NOW,
        native_id="native-1",
    )
    dispatch(state, OP, "ingest-event", event, NOW)
    with pytest.raises(DomainError):
        dispatch(
            state,
            OP,
            "ingest-event",
            event.model_copy(update={"id": "other", "event": "bulk-export"}),
            NOW,
        )
    with pytest.raises(DomainError):
        dispatch(
            state,
            OP,
            "ingest-event",
            event.model_copy(update={"occurred_at": "2026-11-03T00:00:00Z"}),
            NOW,
        )
    with pytest.raises(DomainError):
        dispatch(
            state,
            OP,
            "record-correction",
            Correct(
                id="gateway",
                version=1,
                scopes=[],
                modify_all_data=False,
                mfa_required=True,
                observed_at="2026-01-01T00:00:00Z",
                source_sha256="b" * 64,
            ),
            NOW,
        )
    with pytest.raises(DomainError):
        view(state, DEMO_IDENTITIES["demo-support"], NOW)


def test_actual_gateway_contract_rate_limit_and_tenant(tmp_path) -> None:
    store = Store(tmp_path / "state.db")
    with store.tx() as db:
        db.execute("INSERT INTO state VALUES(?,?)", ("alder", __import__("json").dumps(seed())))
    with backend() as url:
        gateway = Gateway(store, url)
        request = GatewayRequest(integration_id="gateway", resource="synthetic-record-count")
        assert gateway.request(OP, request, NOW)["result"]["record_count"] == 3
        for _ in range(4):
            gateway.request(OP, request, NOW)
        with pytest.raises(DomainError) as error:
            gateway.request(OP, request, NOW)
        assert error.value.status == 429
        with pytest.raises(DomainError):
            gateway.request(DEMO_IDENTITIES["demo-other"], request, NOW)
        with pytest.raises(DomainError):
            gateway.request(DEMO_IDENTITIES["demo-auditor"], request, NOW)
    with pytest.raises(ValueError):
        Gateway(store, "http://attacker.invalid/count")
    with store.tx() as db:
        state = store.load(db, "alder")
        state["integration"]["gateway"]["scopes"] = ["*"]
        db.execute(
            "UPDATE state SET payload=? WHERE tenant=?", (__import__("json").dumps(state), "alder")
        )
    with backend() as url:
        with pytest.raises(DomainError):
            Gateway(store, url).request(OP, request, NOW)


def test_salesforce_native_contract_parsing_and_pagination(monkeypatch) -> None:
    original = httpx.Client
    requests = []

    def handler(request):
        requests.append(str(request.url))
        assert request.headers["authorization"] == "Bearer test-local-token"
        if request.url.path == "/services/data/":
            return httpx.Response(200, json=[{"version": "64.0"}])
        if request.url.path.endswith("/query"):
            return httpx.Response(
                200,
                json={
                    "records": [{"Id": "p1", "Name": "Broad", "PermissionsModifyAllData": True}],
                    "done": False,
                    "nextRecordsUrl": "/services/data/v64.0/query/page2",
                },
            )
        return httpx.Response(
            200,
            json={
                "records": [{"Id": "p2", "Name": "Narrow", "PermissionsModifyAllData": False}],
                "done": True,
            },
        )

    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs)
    )
    result = collect("https://fixture.my.salesforce.com", "test-local-token")
    assert len(result["records"]) == 2 and len(requests) == 3
    assert result["mfa_and_oauth_scopes"] == "not_collected"
    with pytest.raises(ValueError):
        collect("https://attacker.invalid", "token")


@pytest.mark.parametrize(
    "payload",
    [
        {"records": [], "done": False, "nextRecordsUrl": "https://attacker.invalid/"},
        {"records": [{"Id": "x", "Name": "X", "PermissionsModifyAllData": "true"}], "done": True},
    ],
)
def test_salesforce_rejects_hostile_pagination_and_native_types(monkeypatch, payload) -> None:
    original = httpx.Client

    def handler(request):
        return httpx.Response(
            200, json=[{"version": "64.0"}] if request.url.path == "/services/data/" else payload
        )

    monkeypatch.setattr(
        httpx, "Client", lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs)
    )
    with pytest.raises(ValueError):
        collect("https://fixture.my.salesforce.com", "test-local-token")
