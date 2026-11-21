"""Regression tests for subscription licensing, trial, offline window, and watermark."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import licensing
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MACHINE = "a" * 32


class LicensingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.data = Path(self.temporary.name)
        self.key = Ed25519PrivateKey.generate()
        self.registry: dict[str, datetime] = {}
        self.now = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
        patches = [
            patch.dict(os.environ, {"PEWVISTA_ENFORCE_LICENSE": "1"}),
            patch.object(licensing, "get_app_data_path", return_value=self.data),
            patch.object(licensing, "TRUSTED_LICENSE_KEYS", (licensing.public_key_hex(self.key),)),
            patch.object(licensing, "get_machine_id", return_value=MACHINE),
            patch.object(licensing, "_read_registry_trial_start", side_effect=lambda: self.registry.get("trial")),
            patch.object(licensing, "_write_registry_trial_start", side_effect=lambda value: self.registry.__setitem__("trial", value)),
            patch.object(licensing, "_now", side_effect=lambda: self.now),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)
        self.addCleanup(self.temporary.cleanup)
        licensing.invalidate_status_cache()

    def token(self, days: int = 30, machine: str = MACHINE, subscription: str = "I-TEST123") -> str:
        payload = {"v": 1, "subscription_id": subscription, "machine_id": machine,
                   "issued_at": self.now.isoformat(), "valid_until": (self.now + timedelta(days=days)).isoformat()}
        return licensing.sign_token(payload, self.key)

    def status(self) -> licensing.LicenseStatus:
        return licensing.get_license_status(force=True)

    def test_trial_runs_15_days_then_shows_watermark(self) -> None:
        self.assertEqual(self.status().state, "trial")
        self.assertEqual(self.status().days_left, 15)
        self.assertEqual(licensing.get_watermark_text(), "")
        self.now += timedelta(days=14, hours=23)
        self.assertEqual(self.status().state, "trial")
        self.now += timedelta(hours=2)
        self.assertEqual(self.status().state, "unlicensed")
        licensing.invalidate_status_cache()
        self.assertEqual(licensing.get_watermark_text(), "NOT LICENSED")

    def test_deleting_license_file_does_not_restart_trial(self) -> None:
        self.status()
        self.now += timedelta(days=20)
        (self.data / licensing.LICENSE_FILE_NAME).unlink()
        self.assertEqual(self.status().state, "unlicensed")

    def test_clock_rollback_does_not_extend_trial(self) -> None:
        self.status()
        self.now += timedelta(days=16)
        self.assertEqual(self.status().state, "unlicensed")
        self.now -= timedelta(days=10)
        self.assertEqual(self.status().state, "unlicensed")

    def test_valid_token_licenses_until_offline_window_ends(self) -> None:
        self.status()
        self.now += timedelta(days=40)
        licensing.install_token(self.token(days=30))
        status = self.status()
        self.assertEqual((status.state, status.subscription_id), ("licensed", "I-TEST123"))
        self.assertEqual(licensing.get_watermark_text(), "")
        self.now += timedelta(days=30, minutes=1)
        self.assertEqual(self.status().state, "unlicensed")

    def test_lapsed_license_does_not_start_a_new_trial(self) -> None:
        licensing.install_token(self.token(days=30))
        self.now += timedelta(days=31)
        self.assertEqual(self.status().state, "unlicensed")

    def test_rejects_tampered_foreign_and_expired_codes(self) -> None:
        token = self.token()
        prefix, payload, signature = token.split(".")
        forged = json.loads(licensing._b64decode(payload))
        forged["valid_until"] = (self.now + timedelta(days=3650)).isoformat()
        tampered = ".".join([prefix, licensing._b64encode(json.dumps(forged).encode()), signature])
        other_key = licensing.sign_token(json.loads(licensing._b64decode(payload)), Ed25519PrivateKey.generate())
        for bad in (tampered, other_key, self.token(machine="b" * 32), self.token(days=-1), "I-NOT-A-CODE-" + "x"):
            with self.subTest(bad=bad[:20]):
                with self.assertRaises(licensing.LicenseError):
                    licensing.install_token(bad)

    def test_manual_code_activates_offline_and_carries_modular_capabilities(self) -> None:
        caps = licensing.LicenseCapabilities(
            max_devices=4,
            fixed_secondary_screens=2,
            fixed_sub_secondary_screens=1,
            wireless_devices=4,
            wireless_operator_controller=True,
            private_screen=True,
        )
        code = licensing.issue_manual_token(
            MACHINE,
            "Grace Church",
            days=31,
            private_key=self.key,
            subscription_id="SUB_PAYSTACK99",
            capabilities=caps,
        )
        with patch.object(licensing, "LICENSE_SERVER_URL", ""):
            status = licensing.activate_subscription(code)
        self.assertEqual(status.state, "licensed")
        self.assertEqual(status.subscription_id, "SUB_PAYSTACK99")
        self.assertEqual(status.capabilities, caps)
        self.assertEqual(licensing.calculate_modular_price_zar(caps), 200 + (3 * 75) + 50 + 50 + (4 * 25) + 75 + 50)

    def test_paystack_license_server_checkout_activation_device_limit_and_webhook(self) -> None:
        import hashlib
        import hmac
        import paystack_license_server as pls

        service = pls.PaystackLicenseService(
            db_path=self.data / "server.db",
            private_key=self.key,
            secret_key="sk_test_123456",
        )
        caps = licensing.LicenseCapabilities(
            max_devices=2,
            fixed_secondary_screens=1,
            fixed_sub_secondary_screens=1,
            wireless_devices=2,
            wireless_operator_controller=True,
            private_screen=False,
        )
        with patch.object(licensing, "verify_paystack_reference") as mock_verify:
            mock_verify.return_value = {
                "kind": "transaction",
                "valid": True,
                "status": "success",
                "reference": "REF_CHURCH_1",
                "customer_name": "Grace Church",
                "customer_email": "info@grace.org.za",
                "amount_zar": 375.0,
                "currency": "ZAR",
                "days": 31,
                "capabilities": caps,
            }
            reply1 = service.activate_or_refresh({"subscription_id": "ref_church_1", "machine_id": MACHINE})
            self.assertIn("token", reply1)
            status = licensing.install_token(str(reply1["token"]))
            self.assertEqual(status.state, "licensed")
            self.assertEqual(status.capabilities, caps)

            # Second PC succeeds (up to max_devices=2)
            reply2 = service.activate_or_refresh({"subscription_id": "REF_CHURCH_1", "machine_id": "b" * 32})
            self.assertIn("token", reply2)

            # Third PC is rejected until one PC deactivates
            reply3 = service.activate_or_refresh({"subscription_id": "REF_CHURCH_1", "machine_id": "c" * 32})
            self.assertIn("error", reply3)
            self.assertIn("2 PCs", str(reply3["error"]))

            service.deactivate({"subscription_id": "REF_CHURCH_1", "machine_id": "b" * 32})
            reply4 = service.activate_or_refresh({"subscription_id": "REF_CHURCH_1", "machine_id": "c" * 32})
            self.assertIn("token", reply4)

        # Webhook signature verification and subscription revocation
        webhook_payload = json.dumps({
            "event": "subscription.disable",
            "data": {"subscription_code": "REF_CHURCH_1", "customer": {"email": "info@grace.org.za"}},
        }).encode("utf-8")
        bad_code, _ = service.handle_webhook(webhook_payload, "bad_sig")
        self.assertEqual(bad_code, 401)
        valid_sig = hmac.new(b"sk_test_123456", webhook_payload, hashlib.sha512).hexdigest()
        ok_code, _ = service.handle_webhook(webhook_payload, valid_sig)
        self.assertEqual(ok_code, 200)

    def test_license_request_round_trip(self) -> None:
        request = licensing.build_license_request(" Grace   Church ", MACHINE, billing_months=6)
        self.assertEqual(licensing.parse_license_request(request), (MACHINE, "Grace Church"))
        details = licensing.parse_license_request_details(request)
        self.assertEqual(details["billing_months"], 6)
        self.assertEqual(licensing.parse_license_request(MACHINE.upper()), (MACHINE, ""))
        self.assertEqual(licensing.parse_license_request(licensing.build_license_request("", MACHINE)), (MACHINE, ""))
        self.assertEqual(licensing.parse_license_request("hello"), ("", ""))

    def test_unbuilt_services_are_clamped_and_discounts_encoded_in_token(self) -> None:
        raw_caps = licensing.LicenseCapabilities(
            max_devices=1,
            fixed_secondary_screens=3,
            fixed_sub_secondary_screens=2,
            wireless_devices=5,
            wireless_operator_controller=True,
            private_screen=True,
        )
        # While available_services has all add-ons False, clamping resets them to Base (1 PC, 1 Secondary)
        clamped = raw_caps.clamped_to_available_services({
            "extra_secondary_screen": False,
            "sub_secondary_screen": False,
            "wireless_device": False,
            "wireless_operator_controller": False,
            "private_screen": False,
        })
        self.assertEqual(clamped, licensing.LicenseCapabilities(max_devices=1))
        # 12-month license with 15% discount: R200 * 12 = R2400 - 15% (R360) = R2040
        pricing = licensing.calculate_license_pricing(clamped, billing_months=12)
        self.assertEqual(pricing["total_zar"], 2040)
        self.assertEqual(pricing["discount_percent"], 15)
        code = licensing.issue_manual_token(
            MACHINE,
            "Grace Church",
            days=366,
            private_key=self.key,
            capabilities=raw_caps,
            enforce_available_services=True,
        )
        status = licensing.install_token(code)
        self.assertEqual(status.capabilities, licensing.LicenseCapabilities())
        self.assertIn("R2040.00 for 1 year", status.pricing_summary)

    def test_addon_upgrade_for_remaining_days_preserves_existing_devices(self) -> None:
        current_caps = licensing.LicenseCapabilities(max_devices=1, fixed_secondary_screens=1)
        target_caps = licensing.LicenseCapabilities(max_devices=3, fixed_secondary_screens=1)
        # 15 days left of 31-day month, adding 2 extra main devices (+R75/mo each = +R150/mo)
        upgrade = licensing.calculate_addon_upgrade_pricing(
            current_caps,
            target_caps,
            remaining_days=15,
            clamp_unbuilt=True,
        )
        self.assertEqual(upgrade["added_devices"], 2)
        self.assertEqual(upgrade["delta_monthly_zar"], 150)
        self.assertEqual(upgrade["total_zar"], round(150 * (15 / 31.0)))
        self.assertEqual(upgrade["merged_capabilities"].max_devices, 3)

        # Round-trip add-on request text preserves remaining days and merged device count
        active_status = licensing.LicenseStatus(
            state="licensed",
            days_left=15,
            subscription_id="SUB_1",
            valid_until="2026-11-16T12:00:00+00:00",
            capabilities=current_caps,
        )
        req_text = licensing.build_license_request(
            "Grace Church",
            MACHINE,
            capabilities=target_caps,
            current_status=active_status,
        )
        parsed = licensing.parse_license_request_details(req_text)
        self.assertEqual(parsed["remaining_days"], 15)
        self.assertEqual(parsed["capabilities"].max_devices, 3)

    def test_subscription_id_without_server_gives_clear_error(self) -> None:
        with patch.object(licensing, "LICENSE_SERVER_URL", ""):
            with self.assertRaisesRegex(licensing.LicenseError, "not available yet"):
                licensing.activate_subscription("I-ABC")

    def test_source_runs_are_not_enforced(self) -> None:
        with patch.dict(os.environ, {"PEWVISTA_ENFORCE_LICENSE": ""}), patch.object(licensing.sys, "frozen", False, create=True):
            self.assertEqual(self.status().state, "developer")
            self.assertEqual(licensing.get_watermark_text(), "")

    def test_server_activation_refresh_and_revocation(self) -> None:
        test = self
        replies: dict[str, object] = {}
        requests: list[tuple[str, dict]] = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append((self.path, body))
                reply = replies.get(self.path) or {"token": test.token(subscription=body["subscription_id"])}
                data = json.dumps(reply).encode()
                self.send_response(403 if "error" in reply else 200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args) -> None:
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with patch.object(licensing, "LICENSE_SERVER_URL", f"http://127.0.0.1:{server.server_address[1]}"):
            status = licensing.activate_subscription(" i-abc123 ")
            self.assertEqual((status.state, status.subscription_id), ("licensed", "I-ABC123"))
            self.assertEqual(requests[0][0], "/activate")
            self.assertEqual(requests[0][1]["machine_id"], MACHINE)
            self.assertFalse(licensing.refresh_license())
            self.now += timedelta(days=2)
            self.assertTrue(licensing.refresh_license())
            self.assertEqual(requests[-1][0], "/refresh")
            replies["/refresh"] = {"error": "The subscription is cancelled.", "revoked": True}
            self.now += timedelta(days=2)
            self.assertFalse(licensing.refresh_license())
            self.assertNotIn("token", json.loads((self.data / licensing.LICENSE_FILE_NAME).read_text()))
            self.now += timedelta(days=12)
            self.assertEqual(self.status().state, "unlicensed")
            replies["/activate"] = {"error": "This subscription is already used on 2 PCs."}
            with self.assertRaisesRegex(licensing.LicenseError, "2 PCs"):
                licensing.activate_subscription("I-ABC123")


class SecondaryScreenMarkTests(unittest.TestCase):
    def test_state_and_page_carry_license_mark(self) -> None:
        import obs_secondary_display as obs
        self.assertIn('id="licenseMark"', obs.SECONDARY_DISPLAY_HTML)
        self.assertIn("state.license_mark", obs.SECONDARY_DISPLAY_HTML)
        server = obs.SecondaryStateServer()
        self.addCleanup(server.shutdown)
        for mark in ("NOT LICENSED", ""):
            with patch.object(obs, "get_watermark_text", return_value=mark):
                self.assertEqual(server.get_state()["license_mark"], mark)


if __name__ == "__main__":
    unittest.main()
