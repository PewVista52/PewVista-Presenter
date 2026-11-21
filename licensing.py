"""PewVista subscription licensing: 15-day trial, signed per-PC licenses, full offline use.

A license is a token signed by the publisher's Ed25519 key and bound to one PC. Tokens come
from the license server (Paystack subscription code or payment reference -> token) or are issued
manually by the publisher. Once activated, the license works completely offline for the full paid
period (1, 3, 6, or 12 months); an internet connection is only needed when buying or activating
a license. Live pricing and available services are fetched from the public release/update host
(pricing.json alongside latest.json) when opening the License window so price changes take effect
immediately without needing a software update.

License server protocol (JSON over HTTPS, POST to get_license_server_url() + path):
    /activate    {"subscription_id", "machine_id", "machine_name", "app_version"} -> {"token"}
    /refresh     same body                                                        -> {"token"}
    /deactivate  {"subscription_id", "machine_id"}                                -> {"ok": true}
    Errors return {"error": "<message>"}; add "revoked": true when the subscription is not paid.

Publisher commands (run from the source workspace):
    python licensing.py public-key                      Create the key if needed and print it
    python licensing.py issue <machine_id> <name> [--days 31]   Print a manual license code
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app_paths import get_app_base_path, get_app_data_path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError:
    InvalidSignature = None
    serialization = None
    Ed25519PrivateKey = None
    Ed25519PublicKey = None


TRIAL_DAYS = 15
OFFLINE_GRACE_DAYS = 30
MAX_DEVICES = 1
PRICE_PLACEHOLDER = "{PRICE}"
DEFAULT_PRICE_TEXT = "R200.00 per month"
# Default URLs; overridden by Resourses/pricing.json when set in the publisher's License Tool.
LICENSE_SERVER_URL = ""
PAYSTACK_SUBSCRIBE_URL = ""
PAYPAL_SUBSCRIBE_URL = ""
PAYSTACK_API_BASE = "https://api.paystack.co"
LIVE_PRICING_URLS: tuple[str, ...] = (
    "https://raw.githubusercontent.com/PewVista52/PewVista-Presenter/main/Resourses/pricing.json",
    "https://github.com/PewVista52/PewVista-Presenter/releases/latest/download/pricing.json",
)
LIVE_PRICING_CACHE_FILE = "live_pricing.json"
TRUSTED_LICENSE_KEYS: tuple[str, ...] = ("2ef566182c688283b7e4e758f8b7de3e187e5978e564cf893169689fc6a4de90",)
WATERMARK_TEXT = "NOT LICENSED"
TOKEN_PREFIX = "PVL1."
SIGNED_MESSAGE_PREFIX = b"PEWVISTA-LICENSE-V1\n"
LICENSE_FILE_NAME = "license.json"
REFRESH_INTERVAL_SECONDS = 24 * 60 * 60
_REGISTRY_PATH = r"Software\PewVista"
_STATUS_CACHE_SECONDS = 30.0

_status_lock = threading.Lock()
_cached_status: tuple[float, "LicenseStatus"] | None = None


class LicenseError(ValueError):
    """Raised when a license code or server response cannot be used."""


@dataclass(frozen=True)
class LicenseCapabilities:
    """What: Describe the modular screen and device entitlements included in a license.

    Why included: Phase 2 modular pricing calculates a church's subscription from the
    exact screen and device counts they choose and encodes those limits inside the signed
    token so PewVista Presenter enforces them offline and online.
    Where used: LicenseStatus, issue_manual_token(), License Tool, and Paystack checkout.
    """
    max_devices: int = MAX_DEVICES
    fixed_secondary_screens: int = 1
    fixed_sub_secondary_screens: int = 0
    wireless_devices: int = 0
    wireless_operator_controller: bool = False
    private_screen: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "max_devices": max(1, int(self.max_devices)),
            "fixed_secondary_screens": max(1, int(self.fixed_secondary_screens)),
            "fixed_sub_secondary_screens": max(0, int(self.fixed_sub_secondary_screens)),
            "wireless_devices": max(0, int(self.wireless_devices)),
            "wireless_operator_controller": bool(self.wireless_operator_controller),
            "private_screen": bool(self.private_screen),
        }

    def clamped_to_available_services(self, available: dict[str, bool] | None = None) -> "LicenseCapabilities":
        """What: Strip any add-on services that are not yet built/enabled in the program.

        Why included: Churches must never be able to select or be billed for services that
        are still in development.
        """
        avail = available if isinstance(available, dict) else get_available_services()
        return LicenseCapabilities(
            max_devices=max(1, int(self.max_devices)),
            fixed_secondary_screens=max(1, int(self.fixed_secondary_screens)) if avail.get("extra_secondary_screen") else 1,
            fixed_sub_secondary_screens=max(0, int(self.fixed_sub_secondary_screens)) if avail.get("sub_secondary_screen") else 0,
            wireless_devices=max(0, int(self.wireless_devices)) if avail.get("wireless_device") else 0,
            wireless_operator_controller=bool(self.wireless_operator_controller) if avail.get("wireless_operator_controller") else False,
            private_screen=bool(self.private_screen) if avail.get("private_screen") else False,
        )

    @classmethod
    def from_payload(cls, data: object) -> "LicenseCapabilities":
        if not isinstance(data, dict):
            return cls()
        raw = data.get("capabilities") if isinstance(data.get("capabilities"), dict) else data
        def _int(key: str, default: int, minimum: int = 0) -> int:
            try:
                return max(minimum, int(raw.get(key, default)))
            except (TypeError, ValueError):
                return default
        return cls(
            max_devices=_int("max_devices", MAX_DEVICES, 1),
            fixed_secondary_screens=_int("fixed_secondary_screens", 1, 1),
            fixed_sub_secondary_screens=_int("fixed_sub_secondary_screens", 0, 0),
            wireless_devices=_int("wireless_devices", 0, 0),
            wireless_operator_controller=bool(raw.get("wireless_operator_controller", False)),
            private_screen=bool(raw.get("private_screen", False)),
        )

    def summary_text(self) -> str:
        dev_word = "main device" if self.max_devices == 1 else "main devices"
        parts = [f"{self.max_devices} {dev_word}", f"{self.fixed_secondary_screens} fixed secondary screen(s)"]
        if self.fixed_sub_secondary_screens > 0:
            parts.append(f"{self.fixed_sub_secondary_screens} sub secondary screen(s)")
        if self.wireless_devices > 0:
            parts.append(f"{self.wireless_devices} wireless device(s)")
        if self.wireless_operator_controller:
            parts.append("wireless operator controller")
        if self.private_screen:
            parts.append("private screen")
        return ", ".join(parts)


@dataclass(frozen=True)
class LicenseStatus:
    """What: Describe this PC's current license state for the UI and secondary screen.

    Why included: One value drives the watermark, the window title, and the license dialog.
    Where used: get_license_status() callers.
    """
    state: str
    days_left: int = 0
    subscription_id: str = ""
    valid_until: str = ""
    message: str = ""
    capabilities: LicenseCapabilities = LicenseCapabilities()
    pricing_summary: str = ""

    @property
    def is_licensed(self) -> bool:
        return self.state in ("licensed", "developer")

    @property
    def shows_watermark(self) -> bool:
        return self.state == "unlicensed"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def enforcement_enabled() -> bool:
    """What: Decide whether licensing applies to this run.

    Why included: Source runs on the publisher's PC must not be trial-limited, while tests
    and installed builds must enforce licensing.
    Where used: get_license_status().
    Returns: True for frozen builds or when PEWVISTA_ENFORCE_LICENSE=1.
    """
    return bool(getattr(sys, "frozen", False)) or os.environ.get("PEWVISTA_ENFORCE_LICENSE") == "1"


def get_machine_id() -> str:
    """What: Build a stable, anonymous identifier for this Windows PC.

    Why included: Licenses are limited to MAX_DEVICES PCs without sending hardware details.
    Where used: Activation, token checks, and the license dialog.
    Returns: 32 hex characters derived from the Windows MachineGuid.
    """
    raw = ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)) as key:
            raw = str(winreg.QueryValueEx(key, "MachineGuid")[0])
    except (ImportError, OSError):
        raw = f"{uuid.getnode():012x}-{platform.node()}"
    return hashlib.sha256(("PewVista-machine:" + raw.strip().lower()).encode("utf-8")).hexdigest()[:32]


def get_license_file_path() -> Path:
    return get_app_data_path() / LICENSE_FILE_NAME


def _read_store() -> dict[str, object]:
    try:
        value = json.loads(get_license_file_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_store(store: dict[str, object]) -> None:
    path = get_license_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(store, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def _read_registry_trial_start() -> datetime | None:
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REGISTRY_PATH) as key:
            return _parse_time(winreg.QueryValueEx(key, "TrialStarted")[0])
    except (ImportError, OSError):
        return None


def _write_registry_trial_start(started: datetime) -> None:
    try:
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _REGISTRY_PATH) as key:
            winreg.SetValueEx(key, "TrialStarted", 0, winreg.REG_SZ, started.isoformat())
    except (ImportError, OSError):
        pass


def _trusted_keys() -> tuple[str, ...]:
    return TRUSTED_LICENSE_KEYS


def verify_token(token: str, machine_id: str | None = None) -> dict[str, object]:
    """What: Check a license token's signature and that it belongs to this PC.

    Why included: The license file sits in an everyone-writable folder; only the
    publisher's signature makes it trustworthy.
    Where used: Status checks, activation, and manual license codes.
    Returns: The token payload; raises LicenseError when invalid. Expiry is not checked here.
    """
    if Ed25519PublicKey is None:
        raise LicenseError("License checking is unavailable because the 'cryptography' package is missing.")
    text = str(token or "").strip()
    if not text.startswith(TOKEN_PREFIX) or text.count(".") != 2:
        raise LicenseError("This is not a PewVista license code.")
    _, payload_text, signature_text = text.split(".")
    try:
        payload_bytes = _b64decode(payload_text)
        signature = _b64decode(signature_text)
    except ValueError as error:
        raise LicenseError("The license code is damaged.") from error
    for key_hex in _trusted_keys():
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key_hex)).verify(signature, SIGNED_MESSAGE_PREFIX + payload_bytes)
            break
        except (InvalidSignature, ValueError):
            continue
    else:
        raise LicenseError("The license code was not issued by PewVista.")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except ValueError as error:
        raise LicenseError("The license code is damaged.") from error
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise LicenseError("This license code needs a newer version of PewVista.")
    if str(payload.get("machine_id") or "") != (machine_id or get_machine_id()):
        raise LicenseError("This license code belongs to a different PC.")
    if _parse_time(payload.get("valid_until")) is None:
        raise LicenseError("The license code has no expiry date.")
    return payload


def sign_token(payload: dict[str, object], private_key) -> str:
    """What: Sign a license payload with the publisher's private key.

    Why included: Used by the publisher command and the license server.
    Where used: issue_manual_token() and tests.
    Returns: A PVL1 license code string.
    """
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = private_key.sign(SIGNED_MESSAGE_PREFIX + payload_bytes)
    return TOKEN_PREFIX + _b64encode(payload_bytes) + "." + _b64encode(signature)


def invalidate_status_cache() -> None:
    global _cached_status
    with _status_lock:
        _cached_status = None


def get_license_status(force: bool = False) -> LicenseStatus:
    """What: Work out whether this PC is licensed, in trial, or unlicensed.

    Why included: Drives the red secondary-screen marking and the license dialog.
    Where used: Secondary screen state, window title, and Help > License and Subscription.
    Returns: A LicenseStatus; cached briefly because the secondary screen asks often.
    """
    global _cached_status
    with _status_lock:
        if not force and _cached_status is not None and time.monotonic() - _cached_status[0] < _STATUS_CACHE_SECONDS:
            return _cached_status[1]
    status = _compute_status()
    with _status_lock:
        _cached_status = (time.monotonic(), status)
    return status


def _compute_status() -> LicenseStatus:
    store = _read_store()
    now = _now()
    # A clock turned back cannot extend a trial or license beyond the latest time already seen.
    last_seen = _parse_time(store.get("last_seen"))
    effective_now = max(now, last_seen) if last_seen else now
    if not last_seen or now > last_seen + timedelta(hours=1):
        store["last_seen"] = now.isoformat()
        _try_write(store)
    if enforcement_enabled():
        # Record the trial start on first run even when licensed, so a later lapse cannot start a new trial.
        trial_start = _trial_start(store, now)
    else:
        trial_start = now
    token = str(store.get("token") or "")
    if token:
        try:
            payload = verify_token(token)
            valid_until = _parse_time(payload.get("valid_until"))
            if valid_until and effective_now <= valid_until:
                pricing_info = payload.get("pricing") if isinstance(payload.get("pricing"), dict) else {}
                pricing_summary = str(pricing_info.get("summary") or "")
                return LicenseStatus("licensed", days_left=max(0, (valid_until - effective_now).days),
                                     subscription_id=str(payload.get("subscription_id") or ""),
                                     valid_until=valid_until.isoformat(), message="Licensed",
                                     capabilities=LicenseCapabilities.from_payload(payload),
                                     pricing_summary=pricing_summary)
        except LicenseError:
            pass
    if not enforcement_enabled():
        return LicenseStatus("developer", message="Source run: licensing is not enforced.")
    days_used = max(0, (effective_now - trial_start).days)
    if days_used < TRIAL_DAYS:
        return LicenseStatus("trial", days_left=TRIAL_DAYS - days_used, message=f"Free trial: {TRIAL_DAYS - days_used} day(s) left")
    if token:
        return LicenseStatus("unlicensed", message="The license has expired. Connect to the internet or renew the subscription.")
    return LicenseStatus("unlicensed", message="The free trial has ended.")


def _try_write(store: dict[str, object]) -> None:
    try:
        _write_store(store)
    except OSError:
        pass


def _trial_start(store: dict[str, object], now: datetime) -> datetime:
    """What: Return the earliest recorded trial start, recording one on first run.

    Why included: The trial is kept in both the data folder and the user registry so
    deleting one copy does not restart it.
    Where used: _compute_status().
    Returns: The trial start time.
    """
    candidates = [value for value in (_parse_time(store.get("trial_started")), _read_registry_trial_start()) if value]
    started = min(candidates) if candidates else now
    if _parse_time(store.get("trial_started")) != started:
        store["trial_started"] = started.isoformat()
        _try_write(store)
    if _read_registry_trial_start() != started:
        _write_registry_trial_start(started)
    return started


def install_token(token: str) -> LicenseStatus:
    """What: Verify and save a license code for this PC.

    Why included: Activation results and manual codes are stored the same way.
    Where used: activate_subscription(), refresh_license(), and the license dialog.
    Returns: The new license status; raises LicenseError when the code is invalid or expired.
    """
    payload = verify_token(token)
    valid_until = _parse_time(payload.get("valid_until"))
    if valid_until is None or valid_until < _now():
        raise LicenseError("This license code has already expired.")
    store = _read_store()
    store["token"] = str(token).strip()
    store["subscription_id"] = str(payload.get("subscription_id") or "")
    store["last_refresh"] = _now().isoformat()
    _write_store(store)
    invalidate_status_cache()
    return get_license_status(force=True)


def remove_token() -> None:
    store = _read_store()
    for key in ("token", "subscription_id", "last_refresh"):
        store.pop(key, None)
    _write_store(store)
    invalidate_status_cache()


def _app_version() -> str:
    try:
        from windows_update import get_release_version
        return str(get_release_version())
    except Exception:
        return ""


def _post(path: str, body: dict[str, object], timeout: float = 15.0) -> dict[str, object]:
    """What: Send one JSON request to the license server.

    Why included: Activation, refresh, and deactivation share error handling.
    Where used: activate_subscription(), refresh_license(), deactivate_this_pc(), create_paystack_checkout().
    Returns: The decoded JSON reply; raises LicenseError with a readable message.
    """
    server_url = get_license_server_url()
    if not server_url:
        raise LicenseError("Online activation is not available yet. Ask PewVista for a license code.")
    request = urllib.request.Request(server_url.rstrip("/") + path, data=json.dumps(body).encode("utf-8"),
                                     headers={"Content-Type": "application/json", "User-Agent": "PewVista"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            reply = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            reply = json.loads(error.read().decode("utf-8"))
        except ValueError:
            reply = {"error": f"The license server returned an error ({error.code})."}
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise LicenseError("Could not reach the license server. Check the internet connection.") from error
    if not isinstance(reply, dict):
        raise LicenseError("The license server sent an unexpected reply.")
    if reply.get("error"):
        error = LicenseError(str(reply["error"]))
        error.revoked = bool(reply.get("revoked"))
        raise error
    return reply


def _request_body(subscription_id: str) -> dict[str, object]:
    return {"subscription_id": subscription_id, "machine_id": get_machine_id(),
            "machine_name": platform.node()[:64], "app_version": _app_version()}


def activate_subscription(subscription_id: str) -> LicenseStatus:
    """What: Activate this PC with a Paystack subscription code, payment reference, or license code.

    Why included: Churches enter what Paystack emailed them; manual codes also work offline.
    Where used: The license dialog's Activate button.
    Returns: The new status; raises LicenseError with a readable reason.
    """
    value = str(subscription_id or "").strip()
    if value.startswith(TOKEN_PREFIX):
        return install_token(value)
    if not value:
        raise LicenseError("Enter the Paystack subscription code, payment reference, or license code.")
    reply = _post("/activate", _request_body(value.upper()))
    return install_token(str(reply.get("token") or ""))


def create_paystack_checkout(email: str, church_name: str = "",
                             capabilities: LicenseCapabilities | None = None,
                             billing_months: int = 1,
                             upgrade_remaining_days: int = 0,
                             current_capabilities: LicenseCapabilities | None = None) -> dict[str, object]:
    """What: Initialize a dynamic Paystack checkout session via the PewVista license server.

    Why included: Supports standard subscriptions, modular pricing, and mid-term add-on
    upgrades for the remaining days of an active license without altering existing devices.
    Where used: License and Subscription when a license server is configured.
    Returns: A dict with {"authorization_url", "reference", "amount_zar"}.
    """
    clean_email = str(email or "").strip()
    if not clean_email or "@" not in clean_email:
        raise LicenseError("Enter a valid email address for the Paystack receipt and subscription.")
    caps = (capabilities if capabilities is not None else LicenseCapabilities()).clamped_to_available_services()
    body: dict[str, object] = {
        "email": clean_email,
        "church_name": " ".join(str(church_name or "").split())[:80],
        "machine_id": get_machine_id(),
        "machine_name": platform.node()[:64],
        "app_version": _app_version(),
        "billing_months": max(1, int(billing_months)),
        "capabilities": caps.to_dict(),
    }
    if upgrade_remaining_days > 0 and current_capabilities is not None:
        body["upgrade_remaining_days"] = int(upgrade_remaining_days)
        body["current_capabilities"] = current_capabilities.clamped_to_available_services().to_dict()
    return _post("/checkout", body)


def refresh_license() -> bool:
    """What: Renew the token while online so the 30-day offline window keeps moving.

    Why included: Cancelled subscriptions stop renewing; paid ones never see the marking.
    Where used: start_background_refresh() once a day.
    Returns: True when a new token was saved; network failures are silent.
    """
    store = _read_store()
    subscription_id = str(store.get("subscription_id") or "")
    if not subscription_id or not get_license_server_url() or not enforcement_enabled():
        return False
    last_refresh = _parse_time(store.get("last_refresh"))
    if last_refresh and _now() - last_refresh < timedelta(seconds=REFRESH_INTERVAL_SECONDS):
        return False
    try:
        reply = _post("/refresh", _request_body(subscription_id))
        install_token(str(reply.get("token") or ""))
        return True
    except LicenseError as error:
        if getattr(error, "revoked", False):
            remove_token()
        return False


def deactivate_this_pc() -> None:
    """What: Release this PC's license slot so another PC can be activated.

    Why included: Each subscription covers MAX_DEVICES PCs; churches replace computers.
    Where used: The license dialog's Remove button.
    Returns: None; the local license is removed even if the server cannot be reached.
    """
    subscription_id = str(_read_store().get("subscription_id") or "")
    try:
        if subscription_id and get_license_server_url():
            _post("/deactivate", {"subscription_id": subscription_id, "machine_id": get_machine_id()})
    finally:
        remove_token()


def start_background_refresh(on_change=None) -> threading.Thread:
    """What: Refresh the license in the background now and every few hours.

    Why included: Network calls must never block the UI or a live service.
    Where used: main.py at startup.
    Returns: The daemon thread.
    """
    def run() -> None:
        while True:
            try:
                if refresh_license() and on_change is not None:
                    on_change()
            except Exception:
                pass
            time.sleep(6 * 60 * 60)

    thread = threading.Thread(target=run, name="PewVistaLicenseRefresh", daemon=True)
    thread.start()
    return thread


def get_watermark_text() -> str:
    """What: Return the secondary-screen marking for the current license state.

    Why included: Unlicensed copies keep working but show a visible red notice.
    Where used: obs_secondary_display state for the live screen.
    Returns: WATERMARK_TEXT when unlicensed, otherwise an empty string.
    """
    try:
        return WATERMARK_TEXT if get_license_status().shows_watermark else ""
    except Exception:
        return ""


def default_signing_key_path() -> Path:
    configured = os.environ.get("PEWVISTA_LICENSE_KEY", "").strip()
    return Path(configured) if configured else Path.home() / "PewVista Signing" / "license_signing_key.pem"


def load_or_create_signing_key(key_path: Path | None = None):
    """What: Load the publisher's license key, creating it on first use.

    Why included: The private key signs licenses and must never ship with the app.
    Where used: Publisher commands and the future license server.
    Returns: An Ed25519 private key.
    """
    if Ed25519PrivateKey is None:
        raise LicenseError("The 'cryptography' package is required.")
    path = Path(key_path) if key_path is not None else default_signing_key_path()
    if path.is_file():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise LicenseError(f"The license key at {path} is not an Ed25519 key.")
        return key
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key


def public_key_hex(private_key) -> str:
    return private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def issue_manual_token(machine_id: str, customer: str, days: int = 31, private_key=None,
                       subscription_id: str = "", capabilities: LicenseCapabilities | None = None,
                       enforce_available_services: bool = False) -> str:
    """What: Create a license code for one PC without the license server.

    Why included: Lets the publisher license churches that pay another way, verify Paystack
    references directly in License Tool, or encode custom Phase 2 screen/device limits and
    exact pricing breakdown inside the signed license key.
    Where used: The `issue` publisher command, license_tool.pyw, and tests.
    Returns: A PVL1 license code.
    """
    key = private_key if private_key is not None else load_or_create_signing_key()
    issued = _now().replace(microsecond=0)
    sub_id = str(subscription_id or "").strip().upper()
    if not sub_id:
        sub_id = "MANUAL-" + "".join(ch for ch in customer.upper() if ch.isalnum())[:24]
    caps = capabilities if capabilities is not None else LicenseCapabilities()
    if enforce_available_services:
        caps = caps.clamped_to_available_services()
    months = days_to_billing_months(int(days))
    pricing = calculate_license_pricing(caps, billing_months=months, clamp_unbuilt=enforce_available_services)
    payload: dict[str, object] = {
        "v": 1,
        "subscription_id": sub_id,
        "machine_id": machine_id.strip().lower(),
        "customer": customer.strip()[:80],
        "issued_at": issued.isoformat(),
        "valid_until": (issued + timedelta(days=int(days))).isoformat(),
        "capabilities": caps.to_dict(),
        "pricing": pricing,
    }
    return sign_token(payload, key)


def get_pricing_file_path() -> Path:
    return get_app_base_path() / "Resourses" / "pricing.json"


def get_live_pricing_cache_path() -> Path:
    return get_app_data_path() / LIVE_PRICING_CACHE_FILE


DEFAULT_MODULAR_RATES_ZAR: dict[str, int] = {
    "base_zar": 200,
    "extra_main_device_zar": 75,
    "extra_secondary_screen_zar": 50,
    "sub_secondary_screen_zar": 50,
    "wireless_device_zar": 25,
    "wireless_operator_controller_zar": 75,
    "private_screen_zar": 50,
}

DEFAULT_DURATION_DISCOUNTS_PERCENT: dict[str, int] = {
    "1_month": 0,
    "3_months": 5,
    "6_months": 10,
    "12_months": 15,
}

# Services that are currently built vs. still in development (Phase 1 / 2 / 3).
# Unbuilt services are locked so churches can never select or pay for them prematurely.
DEFAULT_AVAILABLE_SERVICES: dict[str, bool] = {
    "extra_secondary_screen": False,
    "sub_secondary_screen": False,
    "wireless_device": False,
    "wireless_operator_controller": False,
    "private_screen": False,
}


def days_to_billing_months(days: int) -> int:
    if days >= 360:
        return 12
    if days >= 180:
        return 6
    if days >= 90:
        return 3
    return max(1, round(days / 31))


def _normalize_pricing_dict(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        raw = {}
    rates = dict(DEFAULT_MODULAR_RATES_ZAR)
    raw_rates = raw.get("modular_rates_zar")
    if isinstance(raw_rates, dict):
        for key in list(rates):
            try:
                if key in raw_rates:
                    rates[key] = max(0, int(raw_rates[key]))
            except (TypeError, ValueError):
                pass
    discounts = dict(DEFAULT_DURATION_DISCOUNTS_PERCENT)
    raw_discounts = raw.get("duration_discounts_percent")
    if isinstance(raw_discounts, dict):
        for key in list(discounts):
            try:
                if key in raw_discounts:
                    discounts[key] = max(0, min(90, int(raw_discounts[key])))
            except (TypeError, ValueError):
                pass
    available = dict(DEFAULT_AVAILABLE_SERVICES)
    raw_available = raw.get("available_services")
    if isinstance(raw_available, dict):
        for key in list(available):
            if key in raw_available:
                available[key] = bool(raw_available[key])
    price = str(raw.get("price") or "").strip() or DEFAULT_PRICE_TEXT
    subscribe_url = str(raw.get("paystack_subscribe_url") or raw.get("paypal_subscribe_url") or "").strip()
    server_url = str(raw.get("license_server_url") or "").strip()
    return {
        "price": price,
        "paystack_subscribe_url": subscribe_url,
        "license_server_url": server_url,
        "modular_rates_zar": rates,
        "duration_discounts_percent": discounts,
        "available_services": available,
    }


def get_pricing_config() -> dict[str, object]:
    """What: Read the pricing, Paystack URLs, modular rate table, duration discounts, and available services.

    Why included: Uses the latest live-fetched pricing cache in the data folder when present
    so price and service changes published to GitHub take effect without shipping a software update.
    Where used: get_price_text(), get_paystack_subscribe_url(), get_license_server_url(),
    and modular price calculation.
    Returns: A dictionary with pricing and public endpoint fields.
    """
    raw: object = {}
    if getattr(sys, "frozen", False):
        cache_path = get_live_pricing_cache_path()
        if cache_path.is_file():
            try:
                raw = json.loads(cache_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raw = {}
    if not isinstance(raw, dict) or not raw:
        try:
            raw = json.loads(get_pricing_file_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = {}
    return _normalize_pricing_dict(raw)


def fetch_live_pricing_config(urls: tuple[str, ...] | None = None, timeout: float = 8.0) -> dict[str, object]:
    """What: Fetch the latest pricing.json from the public update/release host over the internet.

    Why included: When a church opens License and Subscription to buy or renew a license,
    PewVista fetches the current price, discounts, Paystack link, and available services directly
    from the online release feed—no program update needed for price changes.
    Returns: The normalized pricing config (falls back to local config if offline).
    """
    if not getattr(sys, "frozen", False) and urls is None:
        # In the creator's source workspace, Resourses/pricing.json is already the master copy;
        # never overwrite it with an older copy from GitHub before it has been pushed.
        return get_pricing_config()
    candidates = urls if urls is not None else LIVE_PRICING_URLS
    for url in candidates:
        if not url:
            continue
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "PewVista", "Cache-Control": "no-cache"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                fetched = json.loads(response.read(256 * 1024).decode("utf-8"))
            if isinstance(fetched, dict) and fetched.get("price"):
                normalized = _normalize_pricing_dict(fetched)
                try:
                    cache_path = get_live_pricing_cache_path()
                    cache_path.parent.mkdir(parents=True, exist_ok=True)
                    cache_path.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")
                except OSError:
                    pass
                return normalized
        except (urllib.error.URLError, OSError, ValueError):
            continue
    return get_pricing_config()


def get_available_services() -> dict[str, bool]:
    """What: Return which add-on services are currently built and available for licensing."""
    return dict(get_pricing_config()["available_services"])  # type: ignore[arg-type]


def calculate_modular_price_zar(capabilities: LicenseCapabilities | None = None,
                                rates: dict[str, int] | None = None,
                                clamp_unbuilt: bool = False) -> int:
    """What: Calculate the monthly ZAR subscription total for a church's chosen screen/device setup.

    Why included: Supports tiered/modular pricing where churches pay for the base license
    plus any extra PC/Android devices, extra screens, wireless devices, operator remote, or private screen.
    Where used: License Tool, Paystack checkout initialization, and license server.
    Returns: Monthly amount in whole South African Rand (ZAR).
    """
    caps = capabilities if capabilities is not None else LicenseCapabilities()
    if clamp_unbuilt:
        caps = caps.clamped_to_available_services()
    active_rates = rates if isinstance(rates, dict) else get_pricing_config()["modular_rates_zar"]  # type: ignore[assignment]
    base = int(active_rates.get("base_zar", DEFAULT_MODULAR_RATES_ZAR["base_zar"]))
    extra_devices = max(0, caps.max_devices - 1) * int(active_rates.get("extra_main_device_zar", 75))
    extra_secondary = max(0, caps.fixed_secondary_screens - 1) * int(active_rates.get("extra_secondary_screen_zar", 50))
    sub_secondary = max(0, caps.fixed_sub_secondary_screens) * int(active_rates.get("sub_secondary_screen_zar", 50))
    wireless = max(0, caps.wireless_devices) * int(active_rates.get("wireless_device_zar", 25))
    operator_ctrl = int(active_rates.get("wireless_operator_controller_zar", 75)) if caps.wireless_operator_controller else 0
    private_scr = int(active_rates.get("private_screen_zar", 50)) if caps.private_screen else 0
    return max(0, base + extra_devices + extra_secondary + sub_secondary + wireless + operator_ctrl + private_scr)


def calculate_license_pricing(capabilities: LicenseCapabilities | None = None,
                              billing_months: int = 1,
                              rates: dict[str, int] | None = None,
                              discounts: dict[str, int] | None = None,
                              clamp_unbuilt: bool = False) -> dict[str, object]:
    """What: Calculate the full pricing plan breakdown (monthly rate, duration discount, total ZAR) for a license key.

    Why included: Encodes the exact pricing plan, duration discount, and total paid inside
    the signed PVL1 license token so both the publisher and church have a clear record.
    """
    caps = capabilities if capabilities is not None else LicenseCapabilities()
    if clamp_unbuilt:
        caps = caps.clamped_to_available_services()
    cfg = get_pricing_config()
    active_rates = rates if isinstance(rates, dict) else cfg["modular_rates_zar"]  # type: ignore[assignment]
    active_discounts = discounts if isinstance(discounts, dict) else cfg["duration_discounts_percent"]  # type: ignore[assignment]
    months = max(1, int(billing_months))
    monthly_zar = calculate_modular_price_zar(caps, rates=active_rates)
    discount_key = "12_months" if months >= 12 else ("6_months" if months >= 6 else ("3_months" if months >= 3 else "1_month"))
    discount_pct = max(0, min(90, int(active_discounts.get(discount_key, 0))))
    subtotal_zar = monthly_zar * months
    discount_zar = round(subtotal_zar * discount_pct / 100.0)
    total_zar = max(0, subtotal_zar - discount_zar)
    period_label = "1 year" if months == 12 else (f"{months} months" if months > 1 else "1 month")
    if discount_pct > 0:
        summary = f"R{total_zar}.00 for {period_label} ({discount_pct}% discount, R{monthly_zar}.00/mo base)"
    else:
        summary = f"R{total_zar}.00 for {period_label} (R{monthly_zar}.00/mo)"
    return {
        "currency": "ZAR",
        "base_zar": int(active_rates.get("base_zar", DEFAULT_MODULAR_RATES_ZAR["base_zar"])),
        "monthly_zar": monthly_zar,
        "billing_months": months,
        "subtotal_zar": subtotal_zar,
        "discount_percent": discount_pct,
        "discount_zar": discount_zar,
        "total_zar": total_zar,
        "summary": summary,
    }


def calculate_addon_upgrade_pricing(current_capabilities: LicenseCapabilities,
                                    target_capabilities: LicenseCapabilities,
                                    remaining_days: int,
                                    rates: dict[str, int] | None = None,
                                    clamp_unbuilt: bool = False) -> dict[str, object]:
    """What: Calculate the pro-rated ZAR cost to add devices or screens for the remaining days of an active license.

    Why included: When a church is already licensed and wants to add extra PC/Android devices
    (or screens) mid-term, they only pay the difference for their remaining days, and their
    existing device/screen setup and expiry date are preserved.
    """
    cur = current_capabilities.clamped_to_available_services() if clamp_unbuilt else current_capabilities
    raw_target = target_capabilities.clamped_to_available_services() if clamp_unbuilt else target_capabilities
    # Never downgrade existing paid capacities during a mid-term add-on upgrade
    merged = LicenseCapabilities(
        max_devices=max(cur.max_devices, raw_target.max_devices),
        fixed_secondary_screens=max(cur.fixed_secondary_screens, raw_target.fixed_secondary_screens),
        fixed_sub_secondary_screens=max(cur.fixed_sub_secondary_screens, raw_target.fixed_sub_secondary_screens),
        wireless_devices=max(cur.wireless_devices, raw_target.wireless_devices),
        wireless_operator_controller=cur.wireless_operator_controller or raw_target.wireless_operator_controller,
        private_screen=cur.private_screen or raw_target.private_screen,
    )
    active_rates = rates if isinstance(rates, dict) else get_pricing_config()["modular_rates_zar"]  # type: ignore[assignment]
    added_devices = max(0, merged.max_devices - cur.max_devices)
    added_secondary = max(0, merged.fixed_secondary_screens - cur.fixed_secondary_screens)
    added_sub = max(0, merged.fixed_sub_secondary_screens - cur.fixed_sub_secondary_screens)
    added_wireless = max(0, merged.wireless_devices - cur.wireless_devices)
    added_operator = (not cur.wireless_operator_controller) and merged.wireless_operator_controller
    added_private = (not cur.private_screen) and merged.private_screen

    delta_monthly_zar = (
        added_devices * int(active_rates.get("extra_main_device_zar", 75))
        + added_secondary * int(active_rates.get("extra_secondary_screen_zar", 50))
        + added_sub * int(active_rates.get("sub_secondary_screen_zar", 50))
        + added_wireless * int(active_rates.get("wireless_device_zar", 25))
        + (int(active_rates.get("wireless_operator_controller_zar", 75)) if added_operator else 0)
        + (int(active_rates.get("private_screen_zar", 50)) if added_private else 0)
    )
    days_left = max(1, int(remaining_days))
    prorated_zar = max(0, round(delta_monthly_zar * (days_left / 31.0)))
    if delta_monthly_zar > 0 and prorated_zar == 0:
        prorated_zar = 1
    summary = (
        f"R{prorated_zar}.00 for remaining {days_left} day(s) (+R{delta_monthly_zar}.00/mo added)"
        if delta_monthly_zar > 0
        else f"R0.00 (no extra devices/services added; {days_left} day(s) remaining)"
    )
    return {
        "currency": "ZAR",
        "is_upgrade": True,
        "remaining_days": days_left,
        "added_devices": added_devices,
        "delta_monthly_zar": delta_monthly_zar,
        "total_zar": prorated_zar,
        "merged_capabilities": merged,
        "summary": summary,
    }


def get_price_text() -> str:
    """What: Read the subscription price the publisher set in Resourses/pricing.json.

    Why included: One setting drives the app, the Terms and Conditions, and the manual.
    Where used: The license dialog, document display, and the build.
    Returns: Text such as "R200.00 per month"; the default when the file is missing or invalid.
    """
    return str(get_pricing_config().get("price") or DEFAULT_PRICE_TEXT)


def get_paystack_subscribe_url() -> str:
    """What: Return the public Paystack subscription/payment page URL.

    Why included: Allows churches to open the Paystack payment page directly from PewVista.
    Where used: Help > License and Subscription.
    """
    if PAYSTACK_SUBSCRIBE_URL:
        return PAYSTACK_SUBSCRIBE_URL
    if PAYPAL_SUBSCRIBE_URL:
        return PAYPAL_SUBSCRIBE_URL
    return str(get_pricing_config().get("paystack_subscribe_url") or "")


def get_license_server_url() -> str:
    """What: Return the online PewVista license server URL.

    Why included: Allows online Paystack reference/subscription activation and 30-day refresh.
    Where used: _post(), refresh_license(), deactivate_this_pc(), and main.py.
    """
    if LICENSE_SERVER_URL:
        return LICENSE_SERVER_URL
    return str(get_pricing_config().get("license_server_url") or "")


def save_pricing_config(price: str, paystack_subscribe_url: str | None = None,
                        license_server_url: str | None = None,
                        modular_rates_zar: dict[str, int] | None = None,
                        duration_discounts_percent: dict[str, int] | None = None,
                        available_services: dict[str, bool] | None = None) -> None:
    """What: Save the subscription price, Paystack URL, license server URL, modular rates, discounts, and service flags.

    Why included: The publisher's License Tool manages these settings in one place.
    Where used: save_price_text() and license_tool.pyw.
    """
    clean_price = " ".join(str(price or "").split())
    if not clean_price:
        raise ValueError("Enter a price, for example: R200.00 per month")
    current = get_pricing_config()
    updated: dict[str, object] = {
        "price": clean_price,
        "paystack_subscribe_url": (
            str(paystack_subscribe_url).strip()
            if paystack_subscribe_url is not None
            else str(current.get("paystack_subscribe_url") or "")
        ),
        "license_server_url": (
            str(license_server_url).strip()
            if license_server_url is not None
            else str(current.get("license_server_url") or "")
        ),
        "modular_rates_zar": (
            dict(modular_rates_zar)
            if isinstance(modular_rates_zar, dict)
            else dict(current.get("modular_rates_zar") or DEFAULT_MODULAR_RATES_ZAR)  # type: ignore[arg-type]
        ),
        "duration_discounts_percent": (
            dict(duration_discounts_percent)
            if isinstance(duration_discounts_percent, dict)
            else dict(current.get("duration_discounts_percent") or DEFAULT_DURATION_DISCOUNTS_PERCENT)  # type: ignore[arg-type]
        ),
        "available_services": (
            dict(available_services)
            if isinstance(available_services, dict)
            else dict(current.get("available_services") or DEFAULT_AVAILABLE_SERVICES)  # type: ignore[arg-type]
        ),
    }
    get_pricing_file_path().write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")


def save_price_text(price: str) -> None:
    """What: Store a new subscription price while keeping other settings.

    Why included: The publisher's license tool changes the price without editing files.
    Where used: license_tool.pyw.
    Returns: None; raises ValueError for an empty price.
    """
    save_pricing_config(price)


def publish_pricing_electronically(secret_key: str | None = None) -> dict[str, str]:
    """What: Push updated pricing, discounts, and service flags electronically to Paystack and GitHub.

    Why included: When the publisher adjusts pricing in License Tool, it updates online
    immediately without needing to build or send out a software update.
    Returns: Summary dictionary with Paystack and online feed sync results.
    """
    import subprocess
    cfg = get_pricing_config()
    rates = cfg["modular_rates_zar"]  # type: ignore[assignment]
    base_zar = int(rates.get("base_zar", 200))
    paystack_status = "Paystack plan unchanged (no secret key set)."
    key = str(secret_key or load_paystack_secret_key()).strip()
    if key:
        try:
            plans_reply = _paystack_get("/plan", secret_key=key)
            plans = plans_reply.get("data") if isinstance(plans_reply.get("data"), list) else []
            target_plan_code = ""
            for p in plans:
                if isinstance(p, dict) and str(p.get("name") or "") == "PewVista Presenter Base Subscription":
                    target_plan_code = str(p.get("plan_code") or "")
                    break
            amount_kobo = base_zar * 100
            if target_plan_code:
                req = urllib.request.Request(
                    f"{PAYSTACK_API_BASE.rstrip('/')}/plan/{target_plan_code}",
                    data=json.dumps({"amount": amount_kobo, "currency": "ZAR"}).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {key}",
                        "Content-Type": "application/json",
                        "User-Agent": "PewVista-LicenseTool",
                    },
                    method="PUT",
                )
                with urllib.request.urlopen(req, timeout=15.0):
                    pass
                paystack_status = f"Updated Paystack plan ({target_plan_code}) to R{base_zar}.00/month."
            else:
                paystack_status = f"Paystack connected (base R{base_zar}.00/month)."
        except Exception as error:
            paystack_status = f"Paystack plan note: {error}"

    online_status = "Saved locally to Resourses/pricing.json."
    repo_root = get_pricing_file_path().parent.parent
    pricing_rel = "Resourses/pricing.json"
    try:
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.run(
            ["git", "add", pricing_rel],
            cwd=str(repo_root),
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=creation_flags,
        )
        diff = subprocess.run(
            ["git", "diff", "--cached", "--quiet", "--", pricing_rel],
            cwd=str(repo_root),
            capture_output=True,
            timeout=15,
            creationflags=creation_flags,
        )
        if diff.returncode != 0:
            subprocess.run(
                ["git", "commit", "-m", f"Update live pricing configuration ({cfg.get('price')})", "--", pricing_rel],
                cwd=str(repo_root),
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
                creationflags=creation_flags,
            )
            subprocess.run(
                ["git", "push"],
                cwd=str(repo_root),
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=creation_flags,
            )
            online_status = "Published electronically to GitHub live pricing feed (no app update needed)."
        else:
            online_status = "Online GitHub live pricing feed is already up to date."
        # Also upload pricing.json to the latest GitHub Release if one exists so both URLs stay in sync
        subprocess.run(
            ["gh", "release", "upload", "latest", str(get_pricing_file_path()), "--clobber"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=25,
            creationflags=creation_flags,
        )
    except Exception:
        online_status = "Saved to Resourses/pricing.json (connect to internet to sync live feed)."

    return {
        "paystack": paystack_status,
        "online_feed": online_status,
    }


def default_paystack_config_path() -> Path:
    """What: Return the publisher-only Paystack secret config path outside the git repo.

    Why included: The Paystack Secret Key must NEVER be placed in the repository or shipped
    to customer PCs, and living in 'PewVista Signing' means 'Back Up Now' backs it up automatically.
    Where used: load_paystack_secret_key(), save_paystack_secret_key(), license_tool.pyw.
    """
    configured = os.environ.get("PEWVISTA_PAYSTACK_CONFIG", "").strip()
    return Path(configured) if configured else default_signing_key_path().parent / "paystack_config.json"


def load_paystack_secret_key(config_path: Path | None = None) -> str:
    """What: Read the publisher's Paystack Secret Key from PewVista Signing/paystack_config.json.

    Why included: Used by License Tool to verify Paystack transactions/subscriptions and
    check bank payout settings.
    """
    env_key = os.environ.get("PAYSTACK_SECRET_KEY", "").strip()
    if env_key:
        return env_key
    path = Path(config_path) if config_path is not None else default_paystack_config_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(data.get("secret_key") or "").strip() if isinstance(data, dict) else ""


def save_paystack_secret_key(secret_key: str, config_path: Path | None = None) -> Path:
    """What: Save the publisher's Paystack Secret Key in PewVista Signing/paystack_config.json.

    Why included: Stored alongside the private signing keys so it is never committed to GitHub.
    """
    key = str(secret_key or "").strip()
    if key and not (key.startswith("sk_live_") or key.startswith("sk_test_")):
        raise ValueError("A Paystack Secret Key must start with 'sk_live_' or 'sk_test_'.")
    path = Path(config_path) if config_path is not None else default_paystack_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        existing = {}
    if not isinstance(existing, dict):
        existing = {}
    existing["secret_key"] = key
    path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return path


def load_paystack_payout_bank(config_path: Path | None = None) -> dict[str, str]:
    """What: Read the publisher's private payout bank record from PewVista Signing/paystack_config.json.

    Why included: Shown only in the publisher's private License Tool (never in the church app).
    """
    path = Path(config_path) if config_path is not None else default_paystack_config_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    bank = data.get("payout_bank") if isinstance(data, dict) else None
    return {str(k): str(v) for k, v in bank.items()} if isinstance(bank, dict) else {}


def _paystack_get(path: str, secret_key: str | None = None, timeout: float = 15.0) -> dict[str, object]:
    """What: Call the Paystack REST API with the publisher's secret key.

    Why included: Allows the publisher's License Tool to verify customer payments,
    subscriptions, and bank settlement details directly with Paystack.
    """
    key = str(secret_key or load_paystack_secret_key()).strip()
    if not key:
        raise LicenseError("Enter and save your Paystack Secret Key (sk_live_... or sk_test_...) in the License Tool first.")
    url = PAYSTACK_API_BASE.rstrip("/") + "/" + path.lstrip("/")
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
            "User-Agent": "PewVista-LicenseTool",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            reply = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        try:
            reply = json.loads(error.read().decode("utf-8"))
        except ValueError:
            reply = {"status": False, "message": f"Paystack returned HTTP {error.code}."}
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise LicenseError("Could not connect to Paystack. Check your internet connection.") from error
    if not isinstance(reply, dict) or not reply.get("status"):
        msg = str(reply.get("message") or "Paystack rejected the request.") if isinstance(reply, dict) else "Unexpected Paystack response."
        raise LicenseError(msg)
    return reply


def verify_paystack_reference(reference_or_code: str, secret_key: str | None = None) -> dict[str, object]:
    """What: Verify a Paystack transaction reference or subscription code (SUB_...) via Paystack API.

    Why included: Lets the publisher paste a church's Paystack reference or subscription code
    in License Tool, confirm payment status, amount, church/customer info, and any Phase 2
    modular screen capabilities stored in Paystack metadata.
    Returns: Normalized summary dict with status, valid, reference, customer_name, customer_email,
    amount_zar, paid_at, days, capabilities, and raw data.
    """
    ref = str(reference_or_code or "").strip()
    if not ref:
        raise LicenseError("Enter a Paystack payment reference or subscription code (SUB_...).")
    from urllib.parse import quote
    if ref.upper().startswith("SUB_"):
        reply = _paystack_get(f"/subscription/{quote(ref)}", secret_key=secret_key)
        data = reply.get("data") if isinstance(reply.get("data"), dict) else {}
        status = str(data.get("status") or "").lower()
        is_valid = status in ("active", "non-renewing")
        customer = data.get("customer") if isinstance(data.get("customer"), dict) else {}
        plan = data.get("plan") if isinstance(data.get("plan"), dict) else {}
        amount_kobo = int(data.get("amount") or plan.get("amount") or 0)
        email = str(customer.get("email") or "")
        first = str(customer.get("first_name") or "").strip()
        last = str(customer.get("last_name") or "").strip()
        name = " ".join(part for part in (first, last) if part) or email
        interval = str(plan.get("interval") or "monthly").lower()
        days = 366 if interval in ("annually", "yearly") else (183 if interval == "biannually" else (92 if interval == "quarterly" else 31))
        return {
            "kind": "subscription",
            "valid": is_valid,
            "status": status or "unknown",
            "reference": str(data.get("subscription_code") or ref.upper()),
            "customer_name": name,
            "customer_email": email,
            "amount_zar": amount_kobo / 100.0,
            "currency": str(plan.get("currency") or "ZAR"),
            "days": days,
            "capabilities": LicenseCapabilities(),
        }
    reply = _paystack_get(f"/transaction/verify/{quote(ref)}", secret_key=secret_key)
    data = reply.get("data") if isinstance(reply.get("data"), dict) else {}
    status = str(data.get("status") or "").lower()
    is_valid = status == "success"
    customer = data.get("customer") if isinstance(data.get("customer"), dict) else {}
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    amount_kobo = int(data.get("amount") or 0)
    email = str(customer.get("email") or "")
    first = str(customer.get("first_name") or "").strip()
    last = str(customer.get("last_name") or "").strip()
    church_meta = str(metadata.get("church_name") or metadata.get("church") or "").strip()
    name = church_meta or " ".join(part for part in (first, last) if part) or email
    months = 1
    try:
        months = max(1, int(metadata.get("billing_months") or 1))
    except (TypeError, ValueError):
        months = 1
    try:
        rem_days = max(0, int(metadata.get("remaining_days") or 0))
    except (TypeError, ValueError):
        rem_days = 0
    days = rem_days if rem_days > 0 else (366 if months >= 12 else (183 if months >= 6 else (92 if months >= 3 else 31 * months)))
    return {
        "kind": "transaction",
        "valid": is_valid,
        "status": status or "unknown",
        "reference": str(data.get("reference") or ref),
        "customer_name": name,
        "customer_email": email,
        "machine_id": str(metadata.get("machine_id") or "").strip().lower(),
        "amount_zar": amount_kobo / 100.0,
        "currency": str(data.get("currency") or "ZAR"),
        "days": days,
        "capabilities": LicenseCapabilities.from_payload(metadata),
    }


def check_paystack_connection(secret_key: str | None = None) -> dict[str, object]:
    """What: Verify that the Paystack Secret Key is valid and report settlement bank status.

    Why included: Gives the publisher immediate confirmation in License Tool that Paystack
    and bank payouts are connected.
    """
    key = str(secret_key or load_paystack_secret_key()).strip()
    mode = "LIVE" if key.startswith("sk_live_") else ("TEST" if key.startswith("sk_test_") else "UNKNOWN")
    balance_reply = _paystack_get("/balance", secret_key=key)
    balances = balance_reply.get("data") if isinstance(balance_reply.get("data"), list) else []
    balance_text = "Connected"
    if balances and isinstance(balances[0], dict):
        currency = str(balances[0].get("currency") or "ZAR")
        amount = int(balances[0].get("balance") or 0) / 100.0
        balance_text = f"{currency} {amount:,.2f}"
    settlement_info = "Automatic payouts go to your bank account registered in Paystack Dashboard (Compliance > Account / Settings > Accounts)."
    bank = load_paystack_payout_bank()
    if bank.get("bank_name") and bank.get("account_number"):
        settlement_info = (
            f"Payout Bank: {bank.get('bank_name')} {bank.get('account_type', '')} "
            f"#{bank.get('account_number')} (Branch {bank.get('branch_code', '')} — {bank.get('account_holder', '')})."
        )
    try:
        settlements_reply = _paystack_get("/settlement?perPage=1", secret_key=key)
        settlements = settlements_reply.get("data") if isinstance(settlements_reply.get("data"), list) else []
        if settlements and isinstance(settlements[0], dict):
            sub_status = str(settlements[0].get("status") or "")
            settlement_info += f"\nLatest Paystack settlement status: {sub_status}."
    except LicenseError:
        pass
    return {
        "mode": mode,
        "balance": balance_text,
        "settlement_info": settlement_info,
    }


def fill_price_placeholders(text: str) -> str:
    return str(text).replace(PRICE_PLACEHOLDER, get_price_text())


def build_license_request(church_name: str, machine_id: str | None = None,
                          capabilities: LicenseCapabilities | None = None,
                          billing_months: int = 1,
                          current_status: LicenseStatus | None = None) -> str:
    """What: Build the text a church sends to request a license code or mid-term device add-on.

    Why included: The publisher's tool reads the church name, PC ID, billing period or
    remaining paid days, and selected screen/device capacities from it.
    Where used: License and Subscription > Copy ID.
    Returns: A multi-line license request.
    """
    church = " ".join(str(church_name or "").split()) or "(church name not set)"
    caps = (capabilities if capabilities is not None else LicenseCapabilities()).clamped_to_available_services()
    if current_status is not None and current_status.state == "licensed" and current_status.days_left > 0:
        upgrade = calculate_addon_upgrade_pricing(
            current_status.capabilities,
            caps,
            remaining_days=current_status.days_left,
            clamp_unbuilt=True,
        )
        if int(upgrade["delta_monthly_zar"]) > 0:
            merged: LicenseCapabilities = upgrade["merged_capabilities"]  # type: ignore[assignment]
            until_date = current_status.valid_until[:10]
            return (
                f"PewVista license add-on request\n"
                f"Church: {church}\n"
                f"PC ID: {machine_id or get_machine_id()}\n"
                f"Remaining: {current_status.days_left} days (valid until {until_date})\n"
                f"Plan: {merged.summary_text()}\n"
                f"Total: R{upgrade['total_zar']}.00 ({upgrade['summary']})"
            )
    months = max(1, int(billing_months))
    pricing = calculate_license_pricing(caps, billing_months=months, clamp_unbuilt=True)
    period_label = "1 year (366 days)" if months >= 12 else ("6 months (183 days)" if months >= 6 else ("3 months (92 days)" if months >= 3 else "1 month (31 days)"))
    return (
        f"PewVista license request\n"
        f"Church: {church}\n"
        f"PC ID: {machine_id or get_machine_id()}\n"
        f"Period: {period_label}\n"
        f"Plan: {caps.summary_text()}\n"
        f"Total: R{pricing['total_zar']}.00"
    )


def parse_license_request_details(text: str) -> dict[str, object]:
    """What: Parse PC ID, church name, billing months, remaining upgrade days, and selected capabilities from a pasted request."""
    import re
    raw = str(text or "")
    pc_id, church = parse_license_request(raw)
    months = 1
    remaining_days = 0
    rem_match = re.search(r"^\s*Remaining:\s*(\d+)\s*days?", raw, re.MULTILINE | re.IGNORECASE)
    if rem_match:
        remaining_days = max(1, int(rem_match.group(1)))
    period_match = re.search(r"^\s*Period:\s*(.+?)\s*$", raw, re.MULTILINE | re.IGNORECASE)
    if period_match:
        p_txt = period_match.group(1).lower()
        if "1 year" in p_txt or "12" in p_txt or "366" in p_txt:
            months = 12
        elif "6 month" in p_txt or "183" in p_txt:
            months = 6
        elif "3 month" in p_txt or "92" in p_txt:
            months = 3
    plan_match = re.search(r"^\s*Plan:\s*(.+?)\s*$", raw, re.MULTILINE | re.IGNORECASE)
    caps = LicenseCapabilities()
    if plan_match:
        plan_txt = plan_match.group(1).lower()
        sec_m = re.search(r"(\d+)\s+fixed secondary", plan_txt)
        sub_m = re.search(r"(\d+)\s+sub secondary", plan_txt)
        wir_m = re.search(r"(\d+)\s+wireless device", plan_txt)
        dev_m = re.search(r"(\d+)\s+main device", plan_txt)
        caps = LicenseCapabilities(
            max_devices=int(dev_m.group(1)) if dev_m else MAX_DEVICES,
            fixed_secondary_screens=int(sec_m.group(1)) if sec_m else 1,
            fixed_sub_secondary_screens=int(sub_m.group(1)) if sub_m else 0,
            wireless_devices=int(wir_m.group(1)) if wir_m else 0,
            wireless_operator_controller="wireless operator controller" in plan_txt,
            private_screen="private screen" in plan_txt,
        ).clamped_to_available_services()
    return {
        "pc_id": pc_id,
        "church": church,
        "billing_months": months,
        "remaining_days": remaining_days,
        "capabilities": caps,
    }


def parse_license_request(text: str) -> tuple[str, str]:
    """What: Read the PC ID and church name from a pasted license request.

    Why included: Saves the publisher from typing details the church already sent.
    Where used: license_tool.pyw Paste Request.
    Returns: (pc_id, church_name); either is empty when not found.
    """
    import re
    text = str(text or "")
    pc_match = re.search(r"\b([0-9a-fA-F]{32})\b", text)
    church_match = re.search(r"^\s*Church:\s*(.+?)\s*$", text, re.MULTILINE)
    church = church_match.group(1) if church_match else ""
    if church.startswith("(") and church.endswith(")"):
        church = ""
    return (pc_match.group(1).lower() if pc_match else ""), church


def _main(argv: list[str]) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="PewVista license publisher tools")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("public-key", help="Create the license key if needed and print its public key")
    issue = commands.add_parser("issue", help="Print a manual license code for one PC")
    issue.add_argument("machine_id")
    issue.add_argument("customer")
    issue.add_argument("--days", type=int, default=31)
    fill = commands.add_parser("fill-price", help="Replace {PRICE} in packaged documents (used by the build)")
    fill.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args(argv)
    if args.command == "public-key":
        print(public_key_hex(load_or_create_signing_key()))
    elif args.command == "fill-price":
        for path in args.files:
            path.write_text(fill_price_placeholders(path.read_text(encoding="utf-8")), encoding="utf-8")
        print(f"Price set to: {get_price_text()}")
    else:
        print(issue_manual_token(args.machine_id, args.customer, args.days))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
