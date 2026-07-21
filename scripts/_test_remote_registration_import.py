#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class _Handler(BaseHTTPRequestHandler):
    password = " remote-admin-password "
    tokens: set[str] = set()
    login_count = 0
    imported_payload: dict | None = None

    def log_message(self, format: str, *args) -> None:
        return

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        if self.headers.get("X-Admin-Token") in self.tokens:
            return True
        self._send(401, {"detail": "Admin authentication required"})
        return False

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self) -> None:
        if not self._authorized():
            return
        if self.path == "/admin/api/session":
            self._send(200, {"ok": True, "authenticated": True})
            return
        self._send(404, {"detail": "Not found"})

    def do_POST(self) -> None:
        payload = self._read_json()
        if self.path == "/admin/api/login":
            if payload.get("password") != self.password:
                self._send(401, {"detail": "Invalid password"})
                return
            type(self).login_count += 1
            token = f"remote-session-{self.login_count}"
            type(self).tokens.add(token)
            self._send(200, {"ok": True, "token": token})
            return
        if not self._authorized():
            return
        if self.path == "/admin/api/accounts/import":
            type(self).imported_payload = payload
            account = payload.get("payload") or {}
            self._send(
                200,
                {
                    "ok": True,
                    "count": 1,
                    "imported": [
                        {
                            "id": "https://auth.x.ai::remote-account",
                            "email": account.get("email"),
                        }
                    ],
                },
            )
            return
        if self.path.startswith("/admin/api/accounts/") and self.path.endswith("/probe"):
            self._send(
                200,
                {
                    "ok": True,
                    "result": {"model": "grok-4", "latency_ms": 12},
                },
            )
            return
        self._send(404, {"detail": "Not found"})


def main() -> int:
    from grok2api.upstream import grok_build_adapter as adapter

    target_cfg = adapter._validated_remote_import_target(
        "grok.example.com/admin/api/", _Handler.password
    )
    assert target_cfg["base_url"] == "https://grok.example.com"
    assert target_cfg["password"] == _Handler.password

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    target = {"base_url": base_url, "password": _Handler.password}
    try:
        tested = adapter.test_remote_import_target(
            base_url=base_url,
            password=_Handler.password,
        )
        assert tested["ok"] is True

        imported = adapter._remote_import_auth_payload(
            {
                "key": "access-token",
                "refresh_token": "refresh-token",
                "email": "new@example.com",
                "sso": "sso-cookie",
                "sso_backup_path": "C:/local-only/register_sso.json",
            },
            target,
        )
        assert imported["remote"] is True
        assert imported["imported"][0]["id"] == "https://auth.x.ai::remote-account"
        forwarded = (_Handler.imported_payload or {}).get("payload") or {}
        assert forwarded["email"] == "new@example.com"
        assert "sso_backup_path" not in forwarded

        probed = adapter._remote_probe_account(imported["imported"][0]["id"], target)
        assert probed["ok"] is True
        assert _Handler.login_count >= 3

        try:
            adapter.test_remote_import_target(base_url=base_url, password="bad-password")
        except RuntimeError as exc:
            assert "密码错误" in str(exc)
        else:
            raise AssertionError("invalid remote password must fail")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    print("remote registration import: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
