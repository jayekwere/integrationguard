from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx

from app.common import DEMO_IDENTITIES, DomainError, Store, canonical, digest, get, put


def deliver(store: Store, events: list[dict[str, Any]]) -> dict[str, Any]:
    key = secrets.token_bytes(32)
    actor = DEMO_IDENTITIES["demo-operator"]
    body = canonical({"tenant": actor.tenant, "events": events}).encode()
    signature = hmac.new(key, b"integrationguard-events-v1\x00" + body, hashlib.sha256).hexdigest()
    receipt_id = digest(events)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = self.headers.get("Content-Length", "")
            if self.path != "/events" or not length.isdigit() or int(length) > 262144:
                self.send_error(400)
                return
            raw = self.rfile.read(int(length))
            supplied = self.headers.get("X-Event-Signature", "")
            expected = hmac.new(
                key, b"integrationguard-events-v1\x00" + raw, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(supplied, expected):
                self.send_error(403)
                return
            try:
                value = json.loads(raw)
                if value != {"tenant": actor.tenant, "events": events}:
                    raise ValueError("Invalid event contract")
                with store.tx() as db:
                    state = store.load(db, actor.tenant)
                    record = {
                        "id": receipt_id,
                        "events_sha256": digest(value["events"]),
                        "count": len(value["events"]),
                    }
                    put(state, "delivery", receipt_id, record)
                    db.execute(
                        "INSERT INTO state VALUES(?,?) ON CONFLICT(tenant) DO UPDATE SET payload=excluded.payload",
                        (actor.tenant, canonical(state)),
                    )
                output = canonical(record).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(output)))
                self.end_headers()
                self.wfile.write(output)
            except (ValueError, DomainError):
                self.send_error(422)

        def log_message(self, _format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/events"
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=2) as client:
            bad = client.post(url, content=body, headers={"X-Event-Signature": "invalid"})
            assert bad.status_code == 403
            response = client.post(url, content=body, headers={"X-Event-Signature": signature})
            response.raise_for_status()
            replay = client.post(url, content=body, headers={"X-Event-Signature": signature})
            assert replay.json() == response.json()
        with store.tx() as db:
            readback = get(store.load(db, actor.tenant), "delivery", receipt_id)
        assert readback["events_sha256"] == digest(events)
        return {
            "transport": "actual-loopback-http",
            "signature_rejection_verified": True,
            "idempotent_delivery_verified": True,
            "durable_readback": readback,
            "scope": "local_security_event_receiver_not_a_commercial_siem_connector",
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
