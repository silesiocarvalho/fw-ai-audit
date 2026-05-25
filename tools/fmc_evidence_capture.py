"""
fmc_evidence_capture.py
FMC web UI screenshot evidence capture via Playwright.

Protocol (subprocess mode — same pattern as evidence_capture.py for PAN-OS):
  Input  (stdin):  JSON {"host":"x.x.x.x","username":"...","password":"...","methods":[...]}
  Output (stdout): JSON {"method_name": "<base64 PNG>", ...} or {"error": "..."}

Key login detail:
  - FMC allows ONE concurrent web UI session per user.
  - If a REST API token (from the audit) is still active the web UI login
    returns {"error":"session-exists"}.
  - Mitigation: POST /auth/logout before login attempt to clear stale sessions.
  - The subprocess is launched AFTER audit_runner closes the FMC REST session.
"""
from __future__ import annotations

import base64
import json
import ssl
import sys
import time
import urllib.request
from typing import Optional


# ── Check-ID → capture method mapping ────────────────────────────────────────

FMC_EVIDENCE_CHECKS: dict[str, str] = {
    "VER-1":   "capture_system_updates",
    "HA-1":    "capture_device_management",
    "1.1.2":   "capture_admin_users",
    "1.1.3":   "capture_admin_users",
    "1.4.1":   "capture_health_policies",
    "1.4.2.4": "capture_platform_settings",
    "1.4.2.5": "capture_platform_settings",
    "1.4.3":   "capture_platform_settings",
    "2.1.1":   "capture_access_policies",
    "2.1.4":   "capture_access_policies",
    "2.1.6":   "capture_ssl_policies",
}


# ── Capture engine ────────────────────────────────────────────────────────────

class FMCEvidenceCapture:
    """
    Playwright-based screenshot capture for the FMC web UI.

    FMC 7.2.x uses /ddd/#HashName hash-based routing for policy/device pages.
    The /ui/... React Router paths do NOT exist in 7.2.x — they render a silent
    "Page Not Found" inside the SPA without redirecting.

    Confirmed working hashes (FMC 7.2.4):
      /ddd/#SensorList             Devices > Device Management  (HA pairs)
      /ddd/#FirewallPolicyList     Policies > Access Control
      /ddd/#SSLPolicyList          Policies > SSL

    Best-guess hashes for remaining pages (multiple fallbacks in each method):
      /ddd/#SystemUpdates          System > Software  (VDB/SRU versions)
      /ddd/#UserManagement         System > Users  (admin accounts)
      /ddd/#HealthPolicyList       Policies > Health
      /ddd/#PlatformSettingsPolicyList  Devices > Platform Settings
    """

    def __init__(self, host: str, username: str, password: str):
        self.host     = host
        self.username = username
        self.password = password
        self._base    = f"https://{host}"
        self._page    = None
        self._browser = None
        self._pw      = None

    # ── Session management ────────────────────────────────────────────────────

    def _force_logout(self) -> None:
        """POST /auth/logout to clear any existing web UI session."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        try:
            req = urllib.request.Request(
                f"{self._base}/auth/logout", method="POST",
                headers={"Content-Type": "application/json",
                         "User-Agent": "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36"},
            )
            req.data = b""
            urllib.request.urlopen(req, context=ctx, timeout=8)
        except Exception:
            pass

    def connect(self) -> bool:
        """
        Launch Chromium, clear any existing web session, login via the FMC UI.
        Returns True on successful login.
        """
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise RuntimeError("playwright_not_installed")

        # Clear stale sessions before opening browser
        self._force_logout()
        time.sleep(1)

        self._pw      = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=True,
            args=[
                "--ignore-certificate-errors",
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
            ],
        )
        bctx = self._browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1440, "height": 900},
        )
        bctx.add_init_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
        )
        self._page = bctx.new_page()

        # Navigate to login page
        self._page.goto(f"{self._base}/ui/login", wait_until="networkidle", timeout=30000)
        time.sleep(1)

        # Fill credentials using keyboard typing (triggers React state updates)
        self._page.click("input[name='username']")
        self._page.type("input[name='username']", self.username, delay=40)
        self._page.click("input[name='password']")
        self._page.type("input[name='password']", self.password, delay=40)
        time.sleep(0.5)
        self._page.click("button:has-text('Log In')")

        # FMC may show a "Session Exists" modal instead of redirecting.
        # Detect and dismiss it by clicking "End Existing Session".
        try:
            self._page.wait_for_selector(
                "button:has-text('End Existing Session')", timeout=5000
            )
            self._page.click("button:has-text('End Existing Session')")
        except Exception:
            pass  # Dialog did not appear — normal login flow

        # Wait for redirect away from login page
        try:
            self._page.wait_for_url(
                lambda url: "/ui/login" not in url,
                timeout=20000,
            )
        except Exception:
            pass
        time.sleep(3)

        if "/ui/login" in self._page.url:
            return False

        # Dismiss EULA / consent dialogs
        for sel in [
            "button:has-text('OK')",
            "button:has-text('Accept')",
            "button:has-text('I Accept')",
            "button:has-text('Close')",
            "[aria-label='Close']",
        ]:
            try:
                btn = self._page.query_selector(sel)
                if btn and btn.is_visible():
                    btn.click()
                    time.sleep(1)
            except Exception:
                pass

        time.sleep(2)
        return True

    # ── Navigation helpers ────────────────────────────────────────────────────

    def _goto(self, *paths: str, wait_text: Optional[str] = None) -> bool:
        """
        Try each path in order; return True on the first successful navigation.
        Success requires ALL of:
          1. No navigation exception.
          2. No redirect back to the login page.
          3. No "Page Not Found" text (FMC renders this for unknown hash routes
             without changing the URL — the normal 404-redirect doesn't fire).
          4. If wait_text is given, that text must be visible within 8 s.
             A timeout is treated as failure → try the next path.
        """
        for path in paths:
            try:
                self._page.goto(
                    f"{self._base}{path}",
                    wait_until="networkidle",
                    timeout=20000,
                )
                time.sleep(2)
                if "/ui/login" in self._page.url:
                    continue
                # Reject FMC "Page Not Found" — SPA renders this for unknown
                # hash routes without redirecting or changing the URL.
                try:
                    if self._page.query_selector("text=Page Not Found"):
                        continue
                except Exception:
                    pass
                if wait_text:
                    try:
                        self._page.wait_for_selector(
                            f"text={wait_text}", timeout=8000
                        )
                    except Exception:
                        continue   # expected text absent → wrong page, try next
                return True
            except Exception:
                continue
        return False

    def _screenshot(self) -> str:
        """Return a base64-encoded PNG of the current viewport."""
        time.sleep(1)
        png = self._page.screenshot(full_page=False)
        return base64.b64encode(png).decode()

    # ── Capture methods ───────────────────────────────────────────────────────

    def capture_system_updates(self) -> str:
        """System > Software — FMC / VDB / SRU / LSP versions."""
        # FMC 7.2.x uses /ddd/#... hash routing — /ui/... paths 404 silently.
        if self._goto(
            "/ddd/#SystemUpdates",
            "/ddd/#SoftwareUpdate",
            "/ddd/#Updates",
            "/ui/updates",
            "/ui/system/updates",
            wait_text="Update",
        ):
            return self._screenshot()
        return ""

    def capture_device_management(self) -> str:
        """Devices > Device Management — managed FTD devices and HA pairs."""
        if self._goto("/ddd/#SensorList", "/ui/devices/overview", "/ui/devices"):
            return self._screenshot()
        return ""

    def capture_admin_users(self) -> str:
        """System > Users — local and external admin accounts with roles."""
        if self._goto(
            "/ddd/#UserManagement",
            "/ddd/#LocalUser",
            "/ddd/#UserList",
            "/ui/system/users",
            "/ui/admin/users",
            wait_text="User",
        ):
            return self._screenshot()
        return ""

    def capture_health_policies(self) -> str:
        """Policies > Health > Policy — health monitoring modules."""
        if self._goto(
            "/ddd/#HealthPolicyList",
            "/ddd/#HealthMonitorPolicy",
            "/ddd/#HealthPolicy",
            "/ui/health/policies",
            "/ui/health",
            wait_text="Health",
        ):
            return self._screenshot()
        return ""

    def capture_platform_settings(self) -> str:
        """Devices > Platform Settings — SSH/HTTPS access lists, SNMP, NTP."""
        if self._goto(
            "/ddd/#PlatformSettingsPolicyList",
            "/ddd/#PlatformSettings",
            "/ddd/#DevicePlatformSettings",
            "/ui/devices/platformsettings",
            "/ui/devices/platform-settings",
            wait_text="Platform",
        ):
            return self._screenshot()
        return ""

    def capture_access_policies(self) -> str:
        """Policies > Access Control — ACP list with default actions."""
        if self._goto(
            "/ddd/#FirewallPolicyList",
            "/ui/policies/acp",
            "/ui/policies/access-control",
        ):
            return self._screenshot()
        return ""

    def capture_ssl_policies(self) -> str:
        """Policies > SSL — SSL decryption policy list."""
        if self._goto(
            "/ddd/#SSLPolicyList",
            "/ui/policies/ssl",
            "/ui/policies/decryption",
        ):
            return self._screenshot()
        return ""

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def close(self) -> None:
        # Logout BEFORE closing the browser so the session cookie is sent with
        # the request — FMC needs it to identify which session to invalidate.
        try:
            if self._page:
                self._page.evaluate(
                    "() => fetch('/auth/logout', {method:'POST'}).catch(()=>{})"
                )
                time.sleep(1)
        except Exception:
            pass
        try:
            self._browser.close()
        except Exception:
            pass
        try:
            self._pw.stop()
        except Exception:
            pass


# ── Subprocess entry point ────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except ImportError:
        print(json.dumps({"error": "playwright_not_installed"}))
        sys.exit(0)

    try:
        payload  = json.loads(sys.stdin.read())
        host     = payload["host"]
        username = payload["username"]
        password = payload["password"]
        methods  = payload["methods"]
    except Exception as e:
        print(json.dumps({"error": f"bad_input: {e}"}))
        sys.exit(0)

    cap = FMCEvidenceCapture(host=host, username=username, password=password)

    if not cap.connect():
        print(json.dumps({"error": "login_failed_session_exists_or_bad_credentials"}))
        sys.exit(0)

    results: dict[str, str] = {}
    for method in methods:
        fn = getattr(cap, method, None)
        if fn is None:
            results[method] = ""
            continue
        try:
            results[method] = fn() or ""
        except Exception:
            results[method] = ""

    cap.close()
    print(json.dumps(results))
