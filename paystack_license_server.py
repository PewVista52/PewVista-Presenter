"""PewVista Automated Paystack License Server.

Runs as a standalone HTTPS/HTTP Python server or behind Cloudflare Tunnel / Nginx / reverse proxy.
Connects PewVista Presenter directly to Paystack (https://api.paystack.co) and signs PVL1
license tokens with the publisher's Ed25519 key.

Supported endpoints (JSON POST):
  POST /checkout    {"email", "church_name", "machine_id", "billing_months", "capabilities"}
                    -> Initializes a Paystack transaction with exact modular ZAR pricing and
                       metadata; returns {"authorization_url", "reference", "amount_zar"}.
  POST /activate    {"subscription_id", "machine_id", "machine_name", "app_version"}
                    -> Verifies the Paystack subscription code (SUB_...) or payment reference
                       against Paystack API, enforces the 2-device limit (or modular max_devices),
                       and returns {"token": "PVL1..."}.
  POST /refresh     {"subscription_id", "machine_id", "machine_name", "app_version"}
                    -> Re-verifies the Paystack subscription/payment and returns a fresh 30-day
                       token, or {"error": "...", "revoked": true} if cancelled/unpaid.
  POST /deactivate  {"subscription_id", "machine_id"}
                    -> Releases this PC's device slot so another PC can activate.
  POST /webhook     Paystack webhook (verified with x-paystack-signature HMAC-SHA512)
                    -> Automatically records successful payments, renewals, and cancellations.

Environment variables (or loaded from "%USERPROFILE%\\PewVista Signing"):
  PAYSTACK_SECRET_KEY      Paystack secret key (sk_live_... or sk_test_...)
  PEWVISTA_LICENSE_KEY     Path to license_signing_key.pem (optional; defaults to PewVista Signing)
  PEWVISTA_SERVER_DB       Path to SQLite state file (default:PewVista Signing/license_server.db)
  PEWVISTA_SERVER_PORT     Port to listen on (default: 8787)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import licensing

_db_lock = threading.Lock()


def default_server_db_path() -> Path:
    configured = os.environ.get("PEWVISTA_SERVER_DB", "").strip()
    if configured:
        return Path(configured)
    return licensing.default_signing_key_path().parent / "license_server.db"


def _init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subscriptions (
                subscription_id TEXT PRIMARY KEY,
                customer_email TEXT NOT NULL DEFAULT '',
                church_name TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                valid_until TEXT NOT NULL DEFAULT '',
                capabilities_json TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS activated_devices (
                subscription_id TEXT NOT NULL,
                machine_id TEXT NOT NULL,
                machine_name TEXT NOT NULL DEFAULT '',
                app_version TEXT NOT NULL DEFAULT '',
                activated_at TEXT NOT NULL DEFAULT '',
                last_seen_at TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (subscription_id, machine_id)
            )
            """
        )
        conn.commit()


def _paystack_request(method: str, path: str, secret_key: str, body: dict[str, object] | None = None) -> dict[str, object]:
    url = licensing.PAYSTACK_API_BASE.rstrip("/") + "/" + path.lstrip("/")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {secret_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "PewVista-LicenseServer",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=15.0) as resp:
            reply = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        try:
            reply = json.loads(err.read().decode("utf-8"))
        except ValueError:
            reply = {"status": False, "message": f"Paystack HTTP {err.code}"}
    except (urllib.error.URLError, OSError, ValueError) as err:
        raise licensing.LicenseError("Could not reach Paystack to verify the payment.") from err
    if not isinstance(reply, dict) or not reply.get("status"):
        msg = str(reply.get("message") or "Paystack rejected the request.") if isinstance(reply, dict) else "Invalid Paystack reply."
        raise licensing.LicenseError(msg)
    return reply


class PaystackLicenseService:
    """Core state machine for verifying Paystack payments/subscriptions and signing tokens."""

    def __init__(self, db_path: Path | None = None, private_key=None, secret_key: str | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else default_server_db_path()
        self._private_key = private_key
        self._secret_key = secret_key
        _init_db(self.db_path)

    @property
    def private_key(self):
        if self._private_key is None:
            self._private_key = licensing.load_or_create_signing_key()
        return self._private_key

    @property
    def secret_key(self) -> str:
        key = str(self._secret_key if self._secret_key is not None else licensing.load_paystack_secret_key()).strip()
        if not key:
            raise licensing.LicenseError("Server Paystack Secret Key is not configured.")
        return key

    def create_checkout(self, body: dict[str, object]) -> dict[str, object]:
        email = str(body.get("email") or "").strip()
        if not email or "@" not in email:
            raise licensing.LicenseError("Enter a valid email address.")
        church_name = str(body.get("church_name") or "").strip()[:80]
        machine_id = str(body.get("machine_id") or "").strip().lower()
        try:
            months = max(1, min(12, int(body.get("billing_months") or 1)))
        except (TypeError, ValueError):
            months = 1
        caps = licensing.LicenseCapabilities.from_payload(body.get("capabilities")).clamped_to_available_services()
        try:
            upgrade_days = max(0, int(body.get("upgrade_remaining_days") or 0))
        except (TypeError, ValueError):
            upgrade_days = 0
        if upgrade_days > 0 and isinstance(body.get("current_capabilities"), dict):
            cur_caps = licensing.LicenseCapabilities.from_payload(body.get("current_capabilities")).clamped_to_available_services()
            upgrade = licensing.calculate_addon_upgrade_pricing(cur_caps, caps, remaining_days=upgrade_days, clamp_unbuilt=True)
            caps = upgrade["merged_capabilities"]  # type: ignore[assignment]
            total_zar = int(upgrade["total_zar"])
            monthly_zar = licensing.calculate_modular_price_zar(caps, clamp_unbuilt=True)
            pricing: dict[str, object] = {
                "currency": "ZAR",
                "monthly_zar": monthly_zar,
                "billing_months": months,
                "remaining_days": upgrade_days,
                "discount_percent": 0,
                "discount_zar": 0,
                "total_zar": total_zar,
                "summary": str(upgrade["summary"]),
            }
        else:
            pricing = licensing.calculate_license_pricing(caps, billing_months=months, clamp_unbuilt=True)
            total_zar = int(pricing["total_zar"])
            monthly_zar = int(pricing["monthly_zar"])
        amount_kobo = total_zar * 100
        metadata = {
            "church_name": church_name,
            "machine_id": machine_id,
            "billing_months": months,
            "remaining_days": upgrade_days,
            "capabilities": caps.to_dict(),
            "pricing": pricing,
        }
        payload: dict[str, object] = {
            "email": email,
            "amount": amount_kobo,
            "currency": "ZAR",
            "metadata": metadata,
        }
        reply = _paystack_request("POST", "/transaction/initialize", self.secret_key, payload)
        data = reply.get("data") if isinstance(reply.get("data"), dict) else {}
        return {
            "authorization_url": str(data.get("authorization_url") or ""),
            "reference": str(data.get("reference") or ""),
            "amount_zar": total_zar,
            "monthly_zar": monthly_zar,
            "billing_months": months,
            "capabilities": caps.to_dict(),
            "pricing": pricing,
        }

    def _sync_from_paystack(self, subscription_id: str) -> tuple[bool, str, datetime, licensing.LicenseCapabilities, str]:
        """Verify with Paystack or local webhook record. Returns (active, church, valid_until, caps, error_msg)."""
        now = licensing._now()
        with _db_lock, closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute(
                "SELECT status, valid_until, capabilities_json, church_name FROM subscriptions WHERE subscription_id = ?",
                (subscription_id,),
            ).fetchone()
        # Query Paystack live status when secret key is available
        try:
            info = licensing.verify_paystack_reference(subscription_id, secret_key=self.secret_key)
            active = bool(info.get("valid"))
            church = str(info.get("customer_name") or "")
            email = str(info.get("customer_email") or "")
            days = int(info.get("days") or licensing.OFFLINE_GRACE_DAYS)
            caps: licensing.LicenseCapabilities = info.get("capabilities") or licensing.LicenseCapabilities()  # type: ignore[assignment]
            valid_until = now + timedelta(days=max(licensing.OFFLINE_GRACE_DAYS, days))
            status_str = "active" if active else "revoked"
            with _db_lock, closing(sqlite3.connect(self.db_path)) as conn:
                conn.execute(
                    """
                    INSERT INTO subscriptions (subscription_id, customer_email, church_name, status, valid_until, capabilities_json, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(subscription_id) DO UPDATE SET
                        customer_email=excluded.customer_email,
                        church_name=excluded.church_name,
                        status=excluded.status,
                        valid_until=excluded.valid_until,
                        capabilities_json=excluded.capabilities_json,
                        updated_at=excluded.updated_at
                    """,
                    (
                        subscription_id,
                        email,
                        church,
                        status_str,
                        valid_until.isoformat(),
                        json.dumps(caps.to_dict()),
                        now.isoformat(),
                    ),
                )
                conn.commit()
            if not active:
                return False, church, now, caps, "This Paystack subscription or payment is no longer active."
            return True, church, valid_until, caps, ""
        except licensing.LicenseError as error:
            if row is not None:
                status_db, until_db, caps_json, church_db = row
                parsed_until = licensing._parse_time(until_db) or (now + timedelta(days=licensing.OFFLINE_GRACE_DAYS))
                caps_db = licensing.LicenseCapabilities.from_payload(json.loads(caps_json or "{}"))
                if status_db == "active" and parsed_until >= now:
                    return True, str(church_db or ""), parsed_until, caps_db, ""
                return False, str(church_db or ""), parsed_until, caps_db, "The subscription is cancelled or expired."
            raise error

    def activate_or_refresh(self, body: dict[str, object], is_refresh: bool = False) -> dict[str, object]:
        sub_id = str(body.get("subscription_id") or "").strip().upper()
        machine_id = str(body.get("machine_id") or "").strip().lower()
        machine_name = str(body.get("machine_name") or "").strip()[:64]
        app_version = str(body.get("app_version") or "").strip()[:32]
        if not sub_id or not machine_id:
            return {"error": "Missing subscription_id or machine_id."}
        try:
            active, church, sub_until, caps, err_msg = self._sync_from_paystack(sub_id)
        except licensing.LicenseError as error:
            return {"error": str(error)}
        if not active:
            return {"error": err_msg or "The subscription is not active.", "revoked": True}
        now = licensing._now().replace(microsecond=0)
        with _db_lock, closing(sqlite3.connect(self.db_path)) as conn:
            existing = conn.execute(
                "SELECT machine_id FROM activated_devices WHERE subscription_id = ?",
                (sub_id,),
            ).fetchall()
            known_machines = {r[0] for r in existing}
            if machine_id not in known_machines and len(known_machines) >= caps.max_devices:
                return {
                    "error": f"This subscription is already used on {caps.max_devices} PCs. "
                             "Use 'Remove from this PC' on an old computer first."
                }
            conn.execute(
                """
                INSERT INTO activated_devices (subscription_id, machine_id, machine_name, app_version, activated_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(subscription_id, machine_id) DO UPDATE SET
                    machine_name=excluded.machine_name,
                    app_version=excluded.app_version,
                    last_seen_at=excluded.last_seen_at
                """,
                (sub_id, machine_id, machine_name, app_version, now.isoformat(), now.isoformat()),
            )
            conn.commit()
        token_until = sub_until
        months = licensing.days_to_billing_months(max(31, (sub_until - now).days))
        pricing = licensing.calculate_license_pricing(caps, billing_months=months)
        payload = {
            "v": 1,
            "subscription_id": sub_id,
            "machine_id": machine_id,
            "customer": church[:80],
            "issued_at": now.isoformat(),
            "valid_until": token_until.isoformat(),
            "capabilities": caps.to_dict(),
            "pricing": pricing,
        }
        return {"token": licensing.sign_token(payload, self.private_key)}

    def deactivate(self, body: dict[str, object]) -> dict[str, object]:
        sub_id = str(body.get("subscription_id") or "").strip().upper()
        machine_id = str(body.get("machine_id") or "").strip().lower()
        if sub_id and machine_id:
            with _db_lock, closing(sqlite3.connect(self.db_path)) as conn:
                conn.execute(
                    "DELETE FROM activated_devices WHERE subscription_id = ? AND machine_id = ?",
                    (sub_id, machine_id),
                )
                conn.commit()
        return {"ok": True}

    def handle_webhook(self, raw_body: bytes, signature_header: str) -> tuple[int, dict[str, object]]:
        expected = hmac.new(self.secret_key.encode("utf-8"), raw_body, hashlib.sha512).hexdigest()
        if not signature_header or not hmac.compare_digest(expected, signature_header.strip().lower()):
            return 401, {"error": "Invalid Paystack webhook signature."}
        try:
            event = json.loads(raw_body.decode("utf-8"))
        except ValueError:
            return 400, {"error": "Invalid JSON."}
        event_type = str(event.get("event") or "")
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        now = licensing._now()
        sub_code = str(data.get("subscription_code") or data.get("reference") or "").strip().upper()
        if not sub_code:
            return 200, {"ok": True}
        metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        customer = data.get("customer") if isinstance(data.get("customer"), dict) else {}
        email = str(customer.get("email") or "")
        church = str(metadata.get("church_name") or customer.get("first_name") or email)
        caps = licensing.LicenseCapabilities.from_payload(metadata)
        if event_type in ("charge.success", "subscription.create", "invoice.update"):
            months = int(metadata.get("billing_months") or 1) if isinstance(metadata.get("billing_months"), int) else 1
            valid_until = now + timedelta(days=max(31, 31 * months))
            status_str = "active"
        elif event_type in ("subscription.disable", "subscription.not_renew", "invoice.payment_failed"):
            valid_until = now
            status_str = "revoked"
        else:
            return 200, {"ok": True}
        with _db_lock, closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                """
                INSERT INTO subscriptions (subscription_id, customer_email, church_name, status, valid_until, capabilities_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(subscription_id) DO UPDATE SET
                    status=excluded.status,
                    valid_until=excluded.valid_until,
                    updated_at=excluded.updated_at
                """,
                (sub_code, email, church, status_str, valid_until.isoformat(), json.dumps(caps.to_dict()), now.isoformat()),
            )
            conn.commit()
        return 200, {"ok": True}


def make_handler(service: PaystackLicenseService):
    class Handler(BaseHTTPRequestHandler):
        def _send_json(self, code: int, payload: dict[str, object]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length) if length > 0 else b"{}"
            if self.path == "/webhook":
                sig = str(self.headers.get("x-paystack-signature") or "")
                code, reply = service.handle_webhook(raw_body, sig)
                self._send_json(code, reply)
                return
            try:
                body = json.loads(raw_body.decode("utf-8"))
            except ValueError:
                self._send_json(400, {"error": "Invalid JSON request."})
                return
            if self.path == "/checkout":
                try:
                    reply = service.create_checkout(body)
                    self._send_json(200, reply)
                except licensing.LicenseError as error:
                    self._send_json(400, {"error": str(error)})
            elif self.path == "/activate":
                reply = service.activate_or_refresh(body, is_refresh=False)
                self._send_json(403 if "error" in reply else 200, reply)
            elif self.path == "/refresh":
                reply = service.activate_or_refresh(body, is_refresh=True)
                self._send_json(403 if "error" in reply else 200, reply)
            elif self.path == "/deactivate":
                self._send_json(200, service.deactivate(body))
            else:
                self._send_json(404, {"error": "Unknown endpoint."})

        def log_message(self, *args) -> None:
            pass

    return Handler


def run_server(host: str = "0.0.0.0", port: int | None = None) -> None:
    listen_port = port or int(os.environ.get("PEWVISTA_SERVER_PORT") or 8787)
    service = PaystackLicenseService()
    server = ThreadingHTTPServer((host, listen_port), make_handler(service))
    print(f"PewVista Paystack License Server listening on http://{host}:{listen_port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
