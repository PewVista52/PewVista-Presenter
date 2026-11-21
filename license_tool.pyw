"""Publisher tool: create PewVista license codes for church PCs with a simple window.

Uses the private key in "%USERPROFILE%\\PewVista Signing"; never give this tool or the key to customers.
"""

from __future__ import annotations

import re
import shutil
import tkinter as tk
import zipfile
from datetime import date, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import licensing

PROJECT_ROOT = Path(__file__).resolve().parent
RECORDS_PATH = PROJECT_ROOT / "license_records.txt"
DURATIONS = {"1 month (31 days)": 31, "3 months (92 days)": 92, "6 months (183 days)": 183, "1 year (366 days)": 366}
RESTORE_BAT = '@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0restore_pewvista_backup.ps1"\r\n'
README_TEXT = """PEWVISTA BACKUP - {today}
Keep this on a USB drive and a second place. Never share it or put it on GitHub.

TO RESTORE: double-click "Restore PewVista.bat" in this folder.
It puts back your signing keys, grammar checker, license records, and Desktop License Tool icon.
(On a new PC, download the project from GitHub to C:\\PewVista Presenter first:
 https://github.com/PewVista52/PewVista-Presenter)

Contents:
- PewVista Signing    your private keys (license codes and update signing) - MOST IMPORTANT
- grammar.zip         grammar checker needed to build PewVista
- license_records.txt your list of license codes issued (when present)

Your church's own songs and members: in PewVista use Data > Export Databases...
and keep that ZIP next to this backup.
"""


def make_backup(parent_directory: Path) -> Path:
    """What: Create a dated, self-restoring backup folder of everything not on GitHub.

    Why included: Losing the signing keys would stop license codes and updates for every church.
    Where used: The Back Up Now button.
    Returns: The backup folder path.
    """
    keys = licensing.default_signing_key_path().parent
    if not keys.is_dir():
        raise ValueError(f"Your signing keys were not found at {keys}.")
    target = Path(parent_directory) / f"PewVista Backup {date.today().isoformat()}"
    staging = target.with_name(target.name + ".partial")
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    shutil.copytree(keys, staging / "PewVista Signing")
    grammar = PROJECT_ROOT / "Resourses" / "grammar"
    if grammar.is_dir():
        with zipfile.ZipFile(staging / "grammar.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            for path in grammar.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(grammar))
    if RECORDS_PATH.is_file():
        shutil.copy2(RECORDS_PATH, staging / "license_records.txt")
    shutil.copy2(PROJECT_ROOT / "scripts" / "restore_pewvista_backup.ps1", staging / "restore_pewvista_backup.ps1")
    (staging / "Restore PewVista.bat").write_bytes(RESTORE_BAT.encode("ascii"))
    (staging / "README - How to restore.txt").write_text(README_TEXT.format(today=date.today().strftime("%d %B %Y")), encoding="utf-8")
    # Merge into an existing same-day folder: replace only this tool's files and never delete
    # anything else (the publisher may have added a database export there).
    target.mkdir(parents=True, exist_ok=True)
    for item in staging.rglob("*"):
        if item.is_file():
            destination = target / item.relative_to(staging)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, destination)
    shutil.rmtree(staging, ignore_errors=True)
    return target


def create_code(pc_id: str, church: str, days: int,
                subscription_id: str = "",
                capabilities: licensing.LicenseCapabilities | None = None) -> tuple[str, date]:
    """What: Validate the inputs, sign a license code, and record it.

    Why included: Keeps the window logic small and testable.
    Where used: The Create Code button.
    Returns: The code and the date it expires.
    """
    pc_id = pc_id.strip().lower()
    church = church.strip()
    if not re.fullmatch(r"[0-9a-f]{32}", pc_id):
        raise ValueError("The PC ID must be the 32 letters and numbers shown in the church's License window.")
    if not church:
        raise ValueError("Enter the church name.")
    key_path = licensing.default_signing_key_path()
    if not key_path.is_file():
        # Never create a new key here: codes from a new key are rejected by every installed PewVista.
        raise ValueError(f"Your signing key was not found at:\n{key_path}\n\nRestore the 'PewVista Signing' folder from your backup first. "
                         "Do not create a new key; codes made with a new key will not work for churches.")
    key = licensing.load_or_create_signing_key(key_path)
    if licensing.public_key_hex(key) not in licensing.TRUSTED_LICENSE_KEYS:
        raise ValueError("The signing key found does not match PewVista. Restore the original 'PewVista Signing' folder from your backup.")
    caps = (capabilities if capabilities is not None else licensing.LicenseCapabilities()).clamped_to_available_services()
    months = licensing.days_to_billing_months(days)
    pricing = licensing.calculate_license_pricing(caps, billing_months=months, clamp_unbuilt=True)
    code = licensing.issue_manual_token(
        pc_id,
        church,
        days,
        private_key=key,
        subscription_id=subscription_id,
        capabilities=caps,
        enforce_available_services=True,
    )
    expires = date.today() + timedelta(days=days)
    ref_note = f"\t{subscription_id.strip()}" if subscription_id.strip() else ""
    with RECORDS_PATH.open("a", encoding="utf-8") as records:
        records.write(
            f"{date.today().isoformat()}\t{church}\t{pc_id}\t{days} days\t"
            f"valid until {expires.isoformat()}{ref_note}\t{pricing['summary']}\t{caps.summary_text()}\n"
        )
    return code, expires


def main() -> None:
    import webbrowser
    root = tk.Tk()
    root.title("PewVista Presenter - License & Paystack Tool")
    icon = Path(__file__).resolve().parent / "Resourses" / "PewVista.ico"
    if icon.is_file():
        try:
            root.iconbitmap(str(icon))
        except tk.TclError:
            pass
    root.resizable(False, False)
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=10, pady=10)

    # --- TAB 1: Create License Code & Modular Screen Entitlements ---
    body = ttk.Frame(notebook, padding=14)
    notebook.add(body, text="Create License Code")

    ttk.Label(body, text="PC ID (paste the church's license request, or just the PC ID):").grid(row=0, column=0, columnspan=2, sticky="w")
    pc_value = tk.StringVar()
    pc_row = ttk.Frame(body)
    pc_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 8))
    pc_entry = ttk.Entry(pc_row, textvariable=pc_value, width=48)
    pc_entry.pack(side="left", fill="x", expand=True)
    ttk.Label(body, text="Church name:").grid(row=2, column=0, columnspan=2, sticky="w")
    church_value = tk.StringVar()

    def apply_request(text: str) -> bool:
        details = licensing.parse_license_request_details(text)
        pc_id = str(details.get("pc_id") or "")
        church = str(details.get("church") or "")
        if not pc_id:
            return False
        if pc_value.get() != pc_id:
            pc_value.set(pc_id)
        if church:
            church_value.set(church)
        rem_days = int(details.get("remaining_days") or 0)
        if rem_days > 0:
            custom_label = f"Remaining ({rem_days} days)"
            DURATIONS[custom_label] = rem_days
            duration_combo.configure(values=list(DURATIONS))
            duration_value.set(custom_label)
        else:
            months = int(details.get("billing_months") or 1)
            target_days = 366 if months >= 12 else (183 if months >= 6 else (92 if months >= 3 else 31))
            for label, d_val in DURATIONS.items():
                if d_val == target_days:
                    duration_value.set(label)
                    break
        caps = details.get("capabilities")
        if isinstance(caps, licensing.LicenseCapabilities):
            max_devices_var.set(caps.max_devices)
            fixed_sec_var.set(caps.fixed_secondary_screens)
            fixed_sub_var.set(caps.fixed_sub_secondary_screens)
            wireless_dev_var.set(caps.wireless_devices)
            operator_ctrl_var.set(caps.wireless_operator_controller)
            private_scr_var.set(caps.private_screen)
        return True

    def paste_request() -> None:
        try:
            text = root.clipboard_get()
        except tk.TclError:
            text = ""
        if not apply_request(text):
            messagebox.showerror("Paste Request", "No PC ID was found in the copied text. Copy the church's whole license request message, then try again.", parent=root)

    pc_value.trace_add("write", lambda *_: apply_request(pc_value.get()) if len(pc_value.get().strip()) > 32 else None)
    ttk.Button(pc_row, text="Paste Request", command=paste_request).pack(side="left", padx=(8, 0))
    ttk.Entry(body, textvariable=church_value, width=64).grid(row=3, column=0, columnspan=2, sticky="ew", pady=(4, 8))

    ttk.Label(body, text="Paystack Reference / Subscription Code (optional - click Verify to check payment):").grid(row=4, column=0, columnspan=2, sticky="w")
    paystack_ref_value = tk.StringVar()
    ref_row = ttk.Frame(body)
    ref_row.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(4, 8))
    ttk.Entry(ref_row, textvariable=paystack_ref_value, width=48).pack(side="left", fill="x", expand=True)

    ttk.Label(body, text="License length:").grid(row=6, column=0, sticky="w")
    duration_value = tk.StringVar(value="1 month (31 days)")
    duration_combo = ttk.Combobox(body, textvariable=duration_value, values=list(DURATIONS), state="readonly", width=24)
    duration_combo.grid(row=6, column=1, sticky="w")

    # Modular screen/device entitlements (unbuilt services are locked until enabled)
    caps_frame = ttk.LabelFrame(body, text="Licensed Screen & Device Capacities (price shown next to each selection)", padding=(10, 6))
    caps_frame.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(10, 6))
    caps_frame.columnconfigure(2, weight=1)
    max_devices_var = tk.IntVar(value=licensing.MAX_DEVICES)
    fixed_sec_var = tk.IntVar(value=1)
    fixed_sub_var = tk.IntVar(value=0)
    wireless_dev_var = tk.IntVar(value=0)
    operator_ctrl_var = tk.BooleanVar(value=False)
    private_scr_var = tk.BooleanVar(value=False)

    base_price_var = tk.StringVar()
    sec_price_var = tk.StringVar()
    sub_price_var = tk.StringVar()
    wire_price_var = tk.StringVar()
    op_price_var = tk.StringVar()
    priv_price_var = tk.StringVar()
    calc_price_var = tk.StringVar()

    ttk.Label(caps_frame, text="Main Devices (PC/Hub):").grid(row=0, column=0, sticky="w")
    ttk.Spinbox(caps_frame, from_=1, to=10, textvariable=max_devices_var, width=5).grid(row=0, column=1, sticky="w", padx=(6, 12))
    ttk.Label(caps_frame, textvariable=base_price_var, foreground="#1a7f37").grid(row=0, column=2, sticky="w")

    sec_lbl = ttk.Label(caps_frame, text="Fixed Secondary Screens:")
    sec_lbl.grid(row=1, column=0, sticky="w", pady=(4, 0))
    sec_spin = ttk.Spinbox(caps_frame, from_=1, to=10, textvariable=fixed_sec_var, width=5)
    sec_spin.grid(row=1, column=1, sticky="w", padx=(6, 12), pady=(4, 0))
    ttk.Label(caps_frame, textvariable=sec_price_var).grid(row=1, column=2, sticky="w", pady=(4, 0))

    sub_lbl = ttk.Label(caps_frame, text="Sub Secondary Screens:")
    sub_lbl.grid(row=2, column=0, sticky="w", pady=(4, 0))
    sub_spin = ttk.Spinbox(caps_frame, from_=0, to=10, textvariable=fixed_sub_var, width=5)
    sub_spin.grid(row=2, column=1, sticky="w", padx=(6, 12), pady=(4, 0))
    ttk.Label(caps_frame, textvariable=sub_price_var).grid(row=2, column=2, sticky="w", pady=(4, 0))

    wire_lbl = ttk.Label(caps_frame, text="Wireless Devices:")
    wire_lbl.grid(row=3, column=0, sticky="w", pady=(4, 0))
    wire_spin = ttk.Spinbox(caps_frame, from_=0, to=50, textvariable=wireless_dev_var, width=5)
    wire_spin.grid(row=3, column=1, sticky="w", padx=(6, 12), pady=(4, 0))
    ttk.Label(caps_frame, textvariable=wire_price_var).grid(row=3, column=2, sticky="w", pady=(4, 0))

    op_chk = ttk.Checkbutton(caps_frame, text="Wireless Operator Remote", variable=operator_ctrl_var)
    op_chk.grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 0))
    ttk.Label(caps_frame, textvariable=op_price_var).grid(row=4, column=2, sticky="w", pady=(4, 0))

    priv_chk = ttk.Checkbutton(caps_frame, text="Private Screen (Pulpit)", variable=private_scr_var)
    priv_chk.grid(row=5, column=0, columnspan=2, sticky="w", pady=(4, 0))
    ttk.Label(caps_frame, textvariable=priv_price_var).grid(row=5, column=2, sticky="w", pady=(4, 0))

    ttk.Separator(caps_frame).grid(row=6, column=0, columnspan=3, sticky="ew", pady=(6, 4))
    ttk.Label(caps_frame, textvariable=calc_price_var, foreground="#0969da", font=("Segoe UI", 9, "bold")).grid(row=7, column=0, columnspan=3, sticky="w")

    def refresh_service_locks() -> None:
        avail = licensing.get_available_services()
        sec_spin.configure(state="normal" if avail.get("extra_secondary_screen") else "disabled")
        if not avail.get("extra_secondary_screen"):
            fixed_sec_var.set(1)
        sub_spin.configure(state="normal" if avail.get("sub_secondary_screen") else "disabled")
        if not avail.get("sub_secondary_screen"):
            fixed_sub_var.set(0)
        wire_spin.configure(state="normal" if avail.get("wireless_device") else "disabled")
        if not avail.get("wireless_device"):
            wireless_dev_var.set(0)
        op_chk.configure(state="normal" if avail.get("wireless_operator_controller") else "disabled")
        if not avail.get("wireless_operator_controller"):
            operator_ctrl_var.set(False)
        priv_chk.configure(state="normal" if avail.get("private_screen") else "disabled")
        if not avail.get("private_screen"):
            private_scr_var.set(False)

    def current_capabilities() -> licensing.LicenseCapabilities:
        try:
            return licensing.LicenseCapabilities(
                max_devices=int(max_devices_var.get()),
                fixed_secondary_screens=int(fixed_sec_var.get()),
                fixed_sub_secondary_screens=int(fixed_sub_var.get()),
                wireless_devices=int(wireless_dev_var.get()),
                wireless_operator_controller=bool(operator_ctrl_var.get()),
                private_screen=bool(private_scr_var.get()),
            ).clamped_to_available_services()
        except (tk.TclError, ValueError):
            return licensing.LicenseCapabilities()

    def update_calculated_price(*_args) -> None:
        cfg_now = licensing.get_pricing_config()
        rates_now = cfg_now["modular_rates_zar"]  # type: ignore[index]
        avail_now = cfg_now["available_services"]  # type: ignore[index]
        days = DURATIONS.get(duration_value.get(), 31)
        months = licensing.days_to_billing_months(days)
        try:
            dev_cnt = max(1, int(max_devices_var.get()))
        except (tk.TclError, ValueError):
            dev_cnt = 1
        extra_devs = max(0, dev_cnt - 1)
        base_mo = int(rates_now.get("base_zar", 200))
        unit_dev = int(rates_now.get("extra_main_device_zar", 75))
        dev_total_mo = base_mo + (extra_devs * unit_dev)
        if extra_devs > 0:
            base_price_var.set(f"= R{dev_total_mo * months}.00  (1st device R{base_mo}.00/mo + {extra_devs} extra × R{unit_dev}.00/mo)")
        else:
            base_price_var.set(f"= R{base_mo * months}.00  (1st device R{base_mo}.00/mo; +R{unit_dev}.00/mo per extra)")

        if not avail_now.get("extra_secondary_screen"):
            sec_price_var.set("1 included in Base  (extra screens in development)")
        else:
            extra_sec = max(0, int(fixed_sec_var.get() or 1) - 1)
            unit_sec = int(rates_now.get("extra_secondary_screen_zar", 50))
            sec_price_var.set(f"= R{extra_sec * unit_sec * months}.00  (1 included; +{extra_sec} × R{unit_sec}.00/mo)")

        if not avail_now.get("sub_secondary_screen"):
            sub_price_var.set("R0.00  (In Development)")
        else:
            sub_cnt = max(0, int(fixed_sub_var.get() or 0))
            unit_sub = int(rates_now.get("sub_secondary_screen_zar", 50))
            sub_price_var.set(f"= R{sub_cnt * unit_sub * months}.00  ({sub_cnt} × R{unit_sub}.00/mo)")

        if not avail_now.get("wireless_device"):
            wire_price_var.set("R0.00  (In Development)")
        else:
            wire_cnt = max(0, int(wireless_dev_var.get() or 0))
            unit_wire = int(rates_now.get("wireless_device_zar", 25))
            wire_price_var.set(f"= R{wire_cnt * unit_wire * months}.00  ({wire_cnt} × R{unit_wire}.00/mo)")

        if not avail_now.get("wireless_operator_controller"):
            op_price_var.set("R0.00  (In Development)")
        else:
            unit_op = int(rates_now.get("wireless_operator_controller_zar", 75))
            op_amt = unit_op * months if bool(operator_ctrl_var.get()) else 0
            op_price_var.set(f"= R{op_amt}.00  (R{unit_op}.00/mo)")

        if not avail_now.get("private_screen"):
            priv_price_var.set("R0.00  (In Development)")
        else:
            unit_priv = int(rates_now.get("private_screen_zar", 50))
            priv_amt = unit_priv * months if bool(private_scr_var.get()) else 0
            priv_price_var.set(f"= R{priv_amt}.00  (R{unit_priv}.00/mo)")

        caps = current_capabilities()
        pricing = licensing.calculate_license_pricing(caps, billing_months=months, clamp_unbuilt=True)
        calc_price_var.set(f"Total to Pay: {pricing['summary']}  |  {caps.summary_text()}")

    refresh_service_locks()
    for var in (max_devices_var, fixed_sec_var, fixed_sub_var, wireless_dev_var, operator_ctrl_var, private_scr_var, duration_value):
        var.trace_add("write", update_calculated_price)
    update_calculated_price()

    def verify_paystack() -> None:
        ref = paystack_ref_value.get().strip()
        root.configure(cursor="watch")
        root.update()
        try:
            info = licensing.verify_paystack_reference(ref)
        except (licensing.LicenseError, ValueError) as error:
            messagebox.showerror("Verify Paystack Payment", str(error), parent=root)
            return
        finally:
            root.configure(cursor="")
        if info.get("customer_name") and not church_value.get().strip():
            church_value.set(str(info["customer_name"]))
        if info.get("machine_id") and not pc_value.get().strip():
            pc_value.set(str(info["machine_id"]))
        caps = info.get("capabilities")
        if isinstance(caps, licensing.LicenseCapabilities):
            max_devices_var.set(caps.max_devices)
            fixed_sec_var.set(caps.fixed_secondary_screens)
            fixed_sub_var.set(caps.fixed_sub_secondary_screens)
            wireless_dev_var.set(caps.wireless_devices)
            operator_ctrl_var.set(caps.wireless_operator_controller)
            private_scr_var.set(caps.private_screen)
        days = int(info.get("days") or 31)
        for label, d_val in DURATIONS.items():
            if d_val == days:
                duration_value.set(label)
                break
        state_word = "PAID / ACTIVE" if info.get("valid") else f"NOT ACTIVE ({info.get('status')})"
        messagebox.showinfo(
            "Paystack Verification",
            f"Status: {state_word}\n"
            f"Reference: {info.get('reference')}\n"
            f"Customer: {info.get('customer_name')} ({info.get('customer_email')})\n"
            f"Amount: {info.get('currency')} {info.get('amount_zar'):,.2f}",
            parent=root,
        )

    ttk.Button(ref_row, text="Verify on Paystack", command=verify_paystack).pack(side="left", padx=(8, 0))

    ttk.Label(body, text="License code to send to the church:").grid(row=9, column=0, columnspan=2, sticky="w", pady=(10, 0))
    output = tk.Text(body, width=64, height=5, wrap="char", state="disabled")
    output.grid(row=10, column=0, columnspan=2, sticky="ew", pady=(4, 0))
    status_value = tk.StringVar()
    ttk.Label(body, textvariable=status_value, foreground="#1a7f37").grid(row=11, column=0, columnspan=2, sticky="w", pady=(6, 0))

    def show_code(text: str) -> None:
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("1.0", text)
        output.configure(state="disabled")

    def copy_code() -> None:
        text = output.get("1.0", "end").strip()
        if text:
            root.clipboard_clear()
            root.clipboard_append(text)
            status_value.set("Copied. Paste it into your email or WhatsApp with Ctrl+V.")

    def on_create() -> None:
        try:
            code, expires = create_code(
                pc_value.get(),
                church_value.get(),
                DURATIONS[duration_value.get()],
                subscription_id=paystack_ref_value.get(),
                capabilities=current_capabilities(),
            )
        except (ValueError, licensing.LicenseError, OSError) as error:
            messagebox.showerror("Create License Code", str(error), parent=root)
            return
        show_code(code)
        copy_code()
        status_value.set(f"Code created and copied. Valid until {expires:%d %B %Y}. Saved to license_records.txt.")

    def open_records() -> None:
        if RECORDS_PATH.is_file():
            import os
            os.startfile(RECORDS_PATH)
        else:
            messagebox.showinfo("License Records", "No codes have been created yet.", parent=root)

    buttons = ttk.Frame(body)
    buttons.grid(row=8, column=0, columnspan=2, sticky="w", pady=(8, 0))
    ttk.Button(buttons, text="Create Code", command=on_create).pack(side="left")
    ttk.Button(buttons, text="Copy Code", command=copy_code).pack(side="left", padx=(8, 0))
    ttk.Button(buttons, text="View Records", command=open_records).pack(side="left", padx=(8, 0))

    def back_up_now() -> None:
        folder = filedialog.askdirectory(parent=root, title="Choose where to save the backup (for example your USB drive)")
        if not folder:
            return
        root.configure(cursor="watch")
        root.update()
        try:
            target = make_backup(Path(folder))
        except (ValueError, OSError) as error:
            messagebox.showerror("Back Up Now", str(error), parent=root)
            return
        finally:
            root.configure(cursor="")
        messagebox.showinfo("Back Up Now", f"Backup saved to:\n{target}\n\nTo restore on any PC, double-click 'Restore PewVista.bat' in that folder.", parent=root)

    ttk.Button(buttons, text="Back Up Now", command=back_up_now).pack(side="left", padx=(8, 0))

    # --- TAB 2: Paystack, Bank Payouts & Modular Pricing ---
    pay_tab = ttk.Frame(notebook, padding=14)
    notebook.add(pay_tab, text="Paystack, Bank & Pricing")
    cfg = licensing.get_pricing_config()
    rates = cfg["modular_rates_zar"]  # type: ignore[index]
    discounts = cfg["duration_discounts_percent"]  # type: ignore[index]
    avail_cfg = cfg["available_services"]  # type: ignore[index]

    ttk.Label(pay_tab, text="1. Paystack Secret Key (saved privately in PewVista Signing - never uploaded to GitHub):").grid(row=0, column=0, columnspan=2, sticky="w")
    secret_key_var = tk.StringVar(value=licensing.load_paystack_secret_key())
    sk_row = ttk.Frame(pay_tab)
    sk_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 8))
    ttk.Entry(sk_row, textvariable=secret_key_var, width=48, show="*").pack(side="left", fill="x", expand=True)

    def test_and_save_paystack_key() -> None:
        try:
            path = licensing.save_paystack_secret_key(secret_key_var.get())
            if not secret_key_var.get().strip():
                messagebox.showinfo("Paystack Key", "Paystack Secret Key cleared.", parent=root)
                return
            root.configure(cursor="watch")
            root.update()
            status = licensing.check_paystack_connection(secret_key_var.get())
        except (ValueError, licensing.LicenseError, OSError) as error:
            messagebox.showerror("Paystack Connection", str(error), parent=root)
            return
        finally:
            root.configure(cursor="")
        messagebox.showinfo(
            "Paystack Connected",
            f"Connected to Paystack ({status['mode']} mode)!\n"
            f"Paystack Balance: {status['balance']}\n"
            f"{status['settlement_info']}\n\n"
            f"Key saved privately at:\n{path}",
            parent=root,
        )

    ttk.Button(sk_row, text="Save & Test Paystack", command=test_and_save_paystack_key).pack(side="left", padx=(8, 0))
    ttk.Button(
        sk_row,
        text="Open Paystack Bank Account",
        command=lambda: webbrowser.open("https://dashboard.paystack.com/#/compliance/account"),
    ).pack(side="left", padx=(8, 0))

    ttk.Label(pay_tab, text="2. Public Paystack Payment / Subscription Page URL (opened when churches click Subscribe):").grid(row=2, column=0, columnspan=2, sticky="w")
    subscribe_url_var = tk.StringVar(value=str(cfg.get("paystack_subscribe_url") or ""))
    ttk.Entry(pay_tab, textvariable=subscribe_url_var, width=64).grid(row=3, column=0, columnspan=2, sticky="ew", pady=(4, 8))

    ttk.Label(pay_tab, text="3. Automated License Server URL (optional - for instant online activation):").grid(row=4, column=0, columnspan=2, sticky="w")
    server_url_var = tk.StringVar(value=str(cfg.get("license_server_url") or ""))
    ttk.Entry(pay_tab, textvariable=server_url_var, width=64).grid(row=5, column=0, columnspan=2, sticky="ew", pady=(4, 8))

    ttk.Label(pay_tab, text="4. Base Subscription Price Text shown in App, Terms & Manual:").grid(row=6, column=0, columnspan=2, sticky="w")
    price_value = tk.StringVar(value=licensing.get_price_text())
    ttk.Entry(pay_tab, textvariable=price_value, width=40).grid(row=7, column=0, columnspan=2, sticky="w", pady=(4, 8))

    rates_box = ttk.LabelFrame(pay_tab, text="Modular Monthly Rates in ZAR & Service Locks (uncheck unbuilt services)", padding=(10, 6))
    rates_box.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(2, 8))
    base_rate_var = tk.IntVar(value=int(rates.get("base_zar", 200)))
    extra_dev_rate_var = tk.IntVar(value=int(rates.get("extra_main_device_zar", 75)))
    extra_sec_rate_var = tk.IntVar(value=int(rates.get("extra_secondary_screen_zar", 50)))
    sub_sec_rate_var = tk.IntVar(value=int(rates.get("sub_secondary_screen_zar", 50)))
    wireless_rate_var = tk.IntVar(value=int(rates.get("wireless_device_zar", 25)))
    operator_rate_var = tk.IntVar(value=int(rates.get("wireless_operator_controller_zar", 75)))
    private_rate_var = tk.IntVar(value=int(rates.get("private_screen_zar", 50)))

    avail_extra_sec_var = tk.BooleanVar(value=bool(avail_cfg.get("extra_secondary_screen", False)))
    avail_sub_sec_var = tk.BooleanVar(value=bool(avail_cfg.get("sub_secondary_screen", False)))
    avail_wireless_var = tk.BooleanVar(value=bool(avail_cfg.get("wireless_device", False)))
    avail_operator_var = tk.BooleanVar(value=bool(avail_cfg.get("wireless_operator_controller", False)))
    avail_private_var = tk.BooleanVar(value=bool(avail_cfg.get("private_screen", False)))

    ttk.Label(rates_box, text="Base (1 PC/Android + 1 Secondary): R").grid(row=0, column=0, sticky="w")
    ttk.Entry(rates_box, textvariable=base_rate_var, width=7).grid(row=0, column=1, sticky="w", padx=(2, 16))
    ttk.Label(rates_box, text="Each Extra PC/Android Device: R").grid(row=0, column=2, sticky="w")
    ttk.Entry(rates_box, textvariable=extra_dev_rate_var, width=7).grid(row=0, column=3, sticky="w", padx=(2, 0))

    ttk.Checkbutton(rates_box, text="Extra Secondary: R", variable=avail_extra_sec_var).grid(row=1, column=0, sticky="w", pady=(4, 0))
    ttk.Entry(rates_box, textvariable=extra_sec_rate_var, width=7).grid(row=1, column=1, sticky="w", padx=(2, 16), pady=(4, 0))
    ttk.Checkbutton(rates_box, text="Sub Secondary: R", variable=avail_sub_sec_var).grid(row=1, column=2, sticky="w", pady=(4, 0))
    ttk.Entry(rates_box, textvariable=sub_sec_rate_var, width=7).grid(row=1, column=3, sticky="w", padx=(2, 0), pady=(4, 0))

    ttk.Checkbutton(rates_box, text="Each Wireless Device: R", variable=avail_wireless_var).grid(row=2, column=0, sticky="w", pady=(4, 0))
    ttk.Entry(rates_box, textvariable=wireless_rate_var, width=7).grid(row=2, column=1, sticky="w", padx=(2, 16), pady=(4, 0))
    ttk.Checkbutton(rates_box, text="Wireless Operator Remote: R", variable=avail_operator_var).grid(row=2, column=2, sticky="w", pady=(4, 0))
    ttk.Entry(rates_box, textvariable=operator_rate_var, width=7).grid(row=2, column=3, sticky="w", padx=(2, 0), pady=(4, 0))

    ttk.Checkbutton(rates_box, text="Private Screen (Pulpit): R", variable=avail_private_var).grid(row=3, column=0, sticky="w", pady=(4, 0))
    ttk.Entry(rates_box, textvariable=private_rate_var, width=7).grid(row=3, column=1, sticky="w", padx=(2, 16), pady=(4, 0))

    disc_box = ttk.LabelFrame(pay_tab, text="Multi-Month Discounts (%) encoded into License Key Price Plan", padding=(10, 6))
    disc_box.grid(row=9, column=0, columnspan=2, sticky="ew", pady=(2, 8))
    disc_1m_var = tk.IntVar(value=int(discounts.get("1_month", 0)))
    disc_3m_var = tk.IntVar(value=int(discounts.get("3_months", 5)))
    disc_6m_var = tk.IntVar(value=int(discounts.get("6_months", 10)))
    disc_12m_var = tk.IntVar(value=int(discounts.get("12_months", 15)))

    ttk.Label(disc_box, text="1 Month %:").grid(row=0, column=0, sticky="w")
    ttk.Spinbox(disc_box, from_=0, to=90, textvariable=disc_1m_var, width=5).grid(row=0, column=1, sticky="w", padx=(4, 14))
    ttk.Label(disc_box, text="3 Months %:").grid(row=0, column=2, sticky="w")
    ttk.Spinbox(disc_box, from_=0, to=90, textvariable=disc_3m_var, width=5).grid(row=0, column=3, sticky="w", padx=(4, 14))
    ttk.Label(disc_box, text="6 Months %:").grid(row=0, column=4, sticky="w")
    ttk.Spinbox(disc_box, from_=0, to=90, textvariable=disc_6m_var, width=5).grid(row=0, column=5, sticky="w", padx=(4, 14))
    ttk.Label(disc_box, text="1 Year %:").grid(row=0, column=6, sticky="w")
    ttk.Spinbox(disc_box, from_=0, to=90, textvariable=disc_12m_var, width=5).grid(row=0, column=7, sticky="w", padx=(4, 0))

    def save_all_pricing() -> None:
        try:
            new_rates = {
                "base_zar": int(base_rate_var.get()),
                "extra_main_device_zar": int(extra_dev_rate_var.get()),
                "extra_secondary_screen_zar": int(extra_sec_rate_var.get()),
                "sub_secondary_screen_zar": int(sub_sec_rate_var.get()),
                "wireless_device_zar": int(wireless_rate_var.get()),
                "wireless_operator_controller_zar": int(operator_rate_var.get()),
                "private_screen_zar": int(private_rate_var.get()),
            }
            new_discounts = {
                "1_month": int(disc_1m_var.get()),
                "3_months": int(disc_3m_var.get()),
                "6_months": int(disc_6m_var.get()),
                "12_months": int(disc_12m_var.get()),
            }
            new_avail = {
                "extra_secondary_screen": bool(avail_extra_sec_var.get()),
                "sub_secondary_screen": bool(avail_sub_sec_var.get()),
                "wireless_device": bool(avail_wireless_var.get()),
                "wireless_operator_controller": bool(avail_operator_var.get()),
                "private_screen": bool(avail_private_var.get()),
            }
            if int(base_rate_var.get()) > 0 and price_value.get().strip().startswith("R"):
                price_value.set(f"R{int(base_rate_var.get())}.00 per month")
            licensing.save_pricing_config(
                price_value.get(),
                paystack_subscribe_url=subscribe_url_var.get(),
                license_server_url=server_url_var.get(),
                modular_rates_zar=new_rates,
                duration_discounts_percent=new_discounts,
                available_services=new_avail,
            )
            refresh_service_locks()
            update_calculated_price()
            root.configure(cursor="watch")
            root.update()
            sync_result = licensing.publish_pricing_electronically(secret_key_var.get())
        except (ValueError, OSError, tk.TclError) as error:
            messagebox.showerror("Paystack & Pricing", str(error), parent=root)
            return
        finally:
            root.configure(cursor="")
        price_value.set(licensing.get_price_text())
        messagebox.showinfo(
            "Pricing Updated Electronically",
            f"Saved & synced electronically (no program update needed!):\n\n"
            f"- Base price: {licensing.get_price_text()}\n"
            f"- {sync_result['paystack']}\n"
            f"- {sync_result['online_feed']}\n\n"
            "When any church opens Help > License and Subscription with internet connected, "
            "their program automatically loads these new prices.",
            parent=root,
        )

    save_row = ttk.Frame(pay_tab)
    save_row.grid(row=10, column=0, columnspan=2, sticky="w", pady=(6, 0))
    ttk.Button(save_row, text="Save & Update Prices Electronically", command=save_all_pricing).pack(side="left")
    ttk.Button(
        save_row,
        text="Open Paystack Payment Pages",
        command=lambda: webbrowser.open("https://dashboard.paystack.com/#/pages"),
    ).pack(side="left", padx=(8, 0))
    bank_info = licensing.load_paystack_payout_bank()
    bank_summary = (
        f"Connected Payout Bank (private): {bank_info['bank_name']} {bank_info.get('account_type', '')} "
        f"• Acc #{bank_info['account_number']} • Branch {bank_info.get('branch_code', '')} • {bank_info.get('account_holder', '')}"
        if bank_info.get("bank_name") and bank_info.get("account_number")
        else "Note: Your bank account for payouts is managed inside your Paystack Dashboard (Compliance > Account)."
    )
    ttk.Label(
        pay_tab,
        text=bank_summary,
        foreground="#1a7f37",
    ).grid(row=11, column=0, columnspan=2, sticky="w", pady=(8, 0))

    pc_entry.focus_set()
    root.mainloop()


if __name__ == "__main__":
    main()
