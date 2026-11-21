# PewVista Presenter — AI & Developer Instructions

## CRITICAL: Installed Version & Developer Version Run Side-by-Side on This PC
1. **Two completely separate instances exist and often run at the same time on this PC:**
   - **Developer workspace (source run):** `C:\PewVista Presenter`
     - App data: `C:\PewVista Presenter\Data`
     - Private OBS portable runtime: `C:\PewVista Presenter\Resourses\obs_portable`
     - Default OBS WebSocket port: `4456`
   - **Installed customer version:** `C:\Program Files\The Light Ministries\PewVista.exe`
     - Shared app data: `C:\ProgramData\The Light Ministries`
     - Private OBS portable runtime: `%LOCALAPPDATA%\PewVista\The Light Ministries\obs_portable`
     - Default OBS WebSocket port: `4455`
2. **Strict Isolation Rules for Any AI Assistant:**
   - **Never** connect the developer version to the installed version's data (`C:\ProgramData\The Light Ministries`), OBS instance, or ports.
   - **Never** stop, kill, or overwrite the installed version's running processes (`obs64.exe` under `%LOCALAPPDATA%\PewVista\...` or `PewVista.exe` under `C:\Program Files\...`) when testing or developing in `C:\PewVista Presenter`.
   - Remember that when both the installed app and the developer workspace are open at the same time, **two `obs64.exe` instances** (and two sets of `obs-browser-page.exe` processes) are competing for CPU, GPU, and VRAM on this PC (`AMD Ryzen 3 3200U` with `AMD Radeon Vega 3` 512 MB VRAM). Keep OBS and preview rendering lightweight so both can coexist or run smoothly on low-spec hardware.
   - Only build or publish installer/update packages (`PewVista-Presenter-Setup.exe`, `PewVista-Presenter-Update-Windows-x64.zip`) to GitHub Releases when explicitly instructed by the user.
   - **GitHub Releases Asset Rule (MUST BE EXACTLY 6 ASSETS TOTAL):** Always use `publish_github_release.ps1` to publish releases. Upload ONLY these 4 files (`PewVista-Presenter-Setup.exe`, `PewVista-Presenter-Update-Windows-x64.zip`, `latest.json`, `pricing.json`) so that together with GitHub's 2 automatic source archives (`Source code (zip)` and `Source code (tar.gz)`), the release has **exactly 6 assets** (never upload duplicate alias filenames). Always clean up local build staging directories (`dist\releases`, `build\desktop-staging`, `build\release-package`) afterwards.
   - Whenever any feature or user-facing behavior changes, update `OPERATING_MANUAL.txt` in the same change using US English spelling.
