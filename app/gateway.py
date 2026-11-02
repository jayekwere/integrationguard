from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Literal

import httpx
from pydantic import Field

from app.common import Contract, DomainError, Identity, Store, digest, get, require


class GatewayRequest(Contract):
    integration_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    resource: Literal["synthetic-record-count"]


@contextmanager
def backend() -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/count":
                self.send_error(404)
                return
            body = b'{"synthetic":true,"record_count":3}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/count"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class Gateway:
    def __init__(self, store: Store, url: str):
        if not url.startswith("http://127.0.0.1:") or not url.endswith("/count"):
            raise ValueError("Gateway only supports the local synthetic backend")
        self.store = store
        self.url = url
        self.windows: dict[tuple[str, str], list[float]] = {}
        self.lock = threading.Lock()

    def request(self, actor: Identity, request: GatewayRequest, now: str) -> dict[str, Any]:
        require(actor, "operator")
        with self.store.tx() as db:
            item = get(self.store.load(db, actor.tenant), "integration", request.integration_id)
            if item["provider"] != "synthetic-gateway" or set(item["scopes"]) != {"synthetic:read"}:
                raise DomainError("Gateway requires the exact synthetic read scope", 403)
        with self.lock:
            key = (actor.tenant, actor.subject)
            window = [t for t in self.windows.get(key, []) if time.monotonic() - t < 60]
            if len(window) >= 5:
                raise DomainError("Local gateway request limit reached", 429)
            self.windows[key] = [*window, time.monotonic()]
        try:
            with httpx.Client(timeout=2, trust_env=False, follow_redirects=False) as client:
                with client.stream("GET", self.url) as response:
                    if response.status_code != 200:
                        raise DomainError("Backend did not return a successful response", 502)
                    raw = bytearray()
                    for chunk in response.iter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 1024:
                            raise DomainError("Backend response exceeds limit", 502)
            result = json.loads(raw)
            if result != {"synthetic": True, "record_count": 3}:
                raise DomainError("Backend response violates the synthetic contract", 502)
        except (httpx.HTTPError, ValueError) as exc:
            raise DomainError("Local backend unavailable or invalid", 502) from exc
        with self.store.tx() as db:
            self.store.audit(db, actor, "gateway-read", digest(request.model_dump()), result, now)
        return {"transport": "actual-loopback-http", "result": result}
