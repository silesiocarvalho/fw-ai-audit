"""
fmc_audit.py
Cisco Firepower Management Center (FMC) audit engine.
Primary: FMC REST API over HTTPS. No SSH required.
Benchmark: CIS Cisco Firepower Threat Defense Benchmark v1.0.0
48 checks: 21 automated + 27 manual.
"""

from __future__ import annotations

import base64
import datetime
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

PASS           = "PASS"
FAIL           = "FAIL"
MANUAL         = "MANUAL"
SKIPPED        = "SKIPPED"
ERROR          = "ERROR"
RECOMMENDATION = "RECOMMENDATION"


# ── FMC REST API session ──────────────────────────────────────────────────────

class FMCRESTSession:
    """
    FMC REST API session over HTTPS.

    Auth: POST /api/fmc_platform/v1/auth/generatetoken (Basic Auth)
          → X-auth-access-token + DOMAIN_UUID response headers.
    Token lifetime: 30 minutes; auto-refreshed 2 minutes before expiry.
    """

    AUTH_PATH     = "/api/fmc_platform/v1/auth/generatetoken"
    REFRESH_PATH  = "/api/fmc_platform/v1/auth/refreshtoken"
    REVOKE_PATH   = "/api/fmc_platform/v1/auth/revokeaccount"
    LOGOUT_PATH   = "/auth/logout"
    PLATFORM_BASE = "/api/fmc_platform/v1"
    CONFIG_BASE   = "/api/fmc_config/v1/domain"

    TOKEN_LIFETIME     = 30 * 60   # 30 min in seconds
    REFRESH_THRESHOLD  =  2 * 60   # refresh 2 min before expiry

    def __init__(self, host: str, port: int = 443, verify_ssl: bool = False):
        self.host       = host
        self.port       = port
        self.verify_ssl = verify_ssl

        self._token:        str   = None
        self._domain_uuid:  str   = None
        self._token_expiry: float = 0.0

        self._ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ctx.check_hostname = False
            self._ctx.verify_mode    = ssl.CERT_NONE

    # ── Authentication ───────────────────────────────────────────────────────

    def connect(self, username: str, password: str) -> None:
        """Authenticate and obtain access token + domain UUID."""
        import time
        url         = f"https://{self.host}:{self.port}{self.AUTH_PATH}"
        credentials = base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")

        req = urllib.request.Request(
            url, method="POST",
            headers={"Authorization": f"Basic {credentials}",
                     "Content-Type": "application/json"},
        )
        req.data = b""
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=20) as resp:
                self._token       = resp.headers.get("X-auth-access-token")
                self._domain_uuid = resp.headers.get("DOMAIN_UUID")
                self._token_expiry = time.time() + self.TOKEN_LIFETIME
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise ConnectionError(
                f"FMC authentication failed (HTTP {e.code}): {body[:300]}"
            )
        except Exception as e:
            raise ConnectionError(f"FMC connection failed: {e}")

        if not self._token:
            raise ConnectionError(
                "FMC returned no access token — verify credentials and FMC REST API access."
            )
        if not self._domain_uuid:
            self._domain_uuid = self._discover_domain_uuid()

    def _discover_domain_uuid(self) -> str:
        """Fall back: query /api/fmc_platform/v1/info/domain."""
        try:
            data  = self._platform_get("info/domain")
            items = data.get("items", [])
            # Prefer Global / default domain
            for item in items:
                if item.get("name", "").lower() in ("global", "default"):
                    return item.get("uuid", "")
            if items:
                return items[0].get("uuid", "")
        except Exception:
            pass
        return ""

    def _ensure_token(self) -> None:
        import time
        if time.time() >= (self._token_expiry - self.REFRESH_THRESHOLD):
            self._refresh_token()

    def _refresh_token(self) -> None:
        import time
        url = f"https://{self.host}:{self.port}{self.REFRESH_PATH}"
        req = urllib.request.Request(
            url, method="POST",
            headers={"X-auth-access-token": self._token or ""},
        )
        req.data = b""
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=15) as resp:
                new_token = resp.headers.get("X-auth-access-token")
                if new_token:
                    self._token = new_token
                self._token_expiry = time.time() + self.TOKEN_LIFETIME
        except Exception:
            pass  # original token may still be valid

    # ── HTTP helpers ─────────────────────────────────────────────────────────

    def _request(self, method: str, url: str,
                 params: dict = None, body: dict = None) -> Any:
        """Authenticated REST request; returns parsed JSON."""
        self._ensure_token()
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        headers = {
            "X-auth-access-token": self._token or "",
            "Content-Type": "application/json",
            "Accept":       "application/json",
        }
        req = urllib.request.Request(url, method=method, headers=headers)
        if body is not None:
            req.data = json.dumps(body).encode("utf-8")
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"FMC API error HTTP {e.code}: {raw[:300]}")
        except Exception as e:
            raise RuntimeError(f"FMC API request failed: {e}")

    def _platform_get(self, path: str, params: dict = None) -> dict:
        url = f"https://{self.host}:{self.port}{self.PLATFORM_BASE}/{path.lstrip('/')}"
        return self._request("GET", url, params=params)

    def _config_get(self, path: str, params: dict = None) -> dict:
        if not self._domain_uuid:
            raise RuntimeError("FMC domain UUID unavailable — connect() first.")
        url = (f"https://{self.host}:{self.port}"
               f"{self.CONFIG_BASE}/{self._domain_uuid}/{path.lstrip('/')}")
        return self._request("GET", url, params=params)

    def _config_get_paged(self, path: str, limit: int = 1000) -> list:
        """GET all pages of a config endpoint (handles FMC pagination)."""
        items, offset = [], 0
        while True:
            data       = self._config_get(path, params={"limit": limit, "offset": offset})
            page_items = data.get("items", [])
            items.extend(page_items)
            if len(page_items) < limit or not data.get("paging", {}).get("next"):
                break
            offset += limit
        return items

    def _platform_get_paged(self, path: str, limit: int = 1000) -> list:
        items, offset = [], 0
        while True:
            data       = self._platform_get(path, params={"limit": limit, "offset": offset})
            page_items = data.get("items", [])
            items.extend(page_items)
            if len(page_items) < limit or not data.get("paging", {}).get("next"):
                break
            offset += limit
        return items

    def close(self) -> None:
        if not self._token:
            return
        # Try token revocation — FMC 7.2.x returns 405 (unsupported); suppress silently.
        # Token will expire naturally after 30 min.
        try:
            url = f"https://{self.host}:{self.port}{self.REVOKE_PATH}"
            req = urllib.request.Request(
                url, method="DELETE",
                headers={"X-auth-access-token": self._token},
            )
            with urllib.request.urlopen(req, context=self._ctx, timeout=10) as _:
                pass
        except Exception:
            pass
        # POST /auth/logout with the REST token header — FMC uses it to identify
        # which server-side session to invalidate. Critical before evidence capture
        # because FMC allows only 1 concurrent web session per user.
        try:
            url = f"https://{self.host}:{self.port}{self.LOGOUT_PATH}"
            req = urllib.request.Request(
                url, method="POST",
                headers={"X-auth-access-token": self._token or "",
                         "Content-Type": "application/json",
                         "User-Agent": "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36"},
            )
            req.data = b""
            with urllib.request.urlopen(req, context=self._ctx, timeout=8) as _:
                pass
        except Exception:
            pass
        finally:
            self._token = None


# ── Result factory ────────────────────────────────────────────────────────────

def make_result(control_id, description, level, status,
                expected=None, actual=None, remediation="", notes="",
                guidance=None, risk_description="", default_risk_level=""):
    # MANUAL checks with no automated evidence get a default so reports show something
    if status == MANUAL and actual is None:
        actual = "Manual verification required — see guidance steps below."
    r = {
        "control_id":         control_id,
        "description":        description,
        "level":              level,
        "status":             status,
        "expected":           expected,
        "actual":             actual,
        "remediation":        remediation,
        "notes":              notes,
        "risk_description":   risk_description,
        "default_risk_level": default_risk_level,
        "timestamp":          datetime.datetime.utcnow().isoformat() + "Z",
    }
    if guidance is not None:
        r["guidance"] = guidance
    return r


# ── FMC software version lifecycle table ─────────────────────────────────────
# (major, minor) → (end_of_sw_maintenance_ISO, end_of_support_ISO)
_FMC_EOL: dict[tuple[int, int], tuple[str, str]] = {
    (6, 2): ("2019-07-31", "2021-02-07"),
    (6, 4): ("2021-04-30", "2022-10-31"),
    (6, 6): ("2022-07-31", "2023-09-30"),
    (6, 7): ("2022-07-31", "2023-09-30"),
    (7, 0): ("2023-04-30", "2025-01-31"),
    (7, 1): ("2022-10-31", "2024-04-30"),
    (7, 2): ("2024-01-31", "2025-07-31"),
    (7, 4): ("2026-07-31", "2027-01-31"),
    (7, 6): ("2028-01-31", "2029-07-31"),
}


# ── Audit engine ──────────────────────────────────────────────────────────────

class FMCAudit:
    """
    CIS Cisco Firepower Threat Defense Benchmark v1.0.0 — 48 checks
    plus 2 additive checks (VER-1, HA-1) = 50 total.
    23 automated (PASS/FAIL/ERROR) + 27 manual (MANUAL).
    """

    TOTAL_CHECKS = 50
    VENDOR       = "cisco_fmc"
    BENCHMARK    = "CIS Cisco FTD Benchmark v1.0.0"

    def __init__(self, session: FMCRESTSession):
        self.session  = session
        self.results: list[dict] = []

        # Cached API responses — fetched once, reused across checks
        self._platform_policies:  list | None = None
        self._health_policies:    list | None = None
        self._access_policies:    list | None = None   # expanded=true
        self._scheduled_tasks:    list | None = None
        self._ssl_policies:       list | None = None
        self._intrusion_policies: list | None = None
        self._identity_policies:  list | None = None
        self._realms:             list | None = None

    # ── Result collection ────────────────────────────────────────────────────

    def _add(self, result: dict) -> None:
        self.results.append(result)

    # ── Cache helpers ────────────────────────────────────────────────────────

    def _get_platform_policies(self) -> list:
        if self._platform_policies is None:
            try:
                self._platform_policies = self.session._config_get_paged(
                    "policy/platformsettingspolicies"
                )
            except Exception:
                self._platform_policies = []
        return self._platform_policies

    def _get_platform_policy_detail(self, policy_id: str) -> dict:
        try:
            return self.session._config_get(
                f"policy/platformsettingspolicies/{policy_id}"
            )
        except Exception:
            return {}

    def _get_first_platform_policy_detail(self) -> dict:
        policies = self._get_platform_policies()
        if not policies:
            return {}
        return self._get_platform_policy_detail(policies[0].get("id", ""))

    def _get_health_policies(self) -> list:
        if self._health_policies is None:
            try:
                self._health_policies = self.session._config_get_paged(
                    "policy/healthpolicies"
                )
            except Exception:
                self._health_policies = []
        return self._health_policies

    def _get_access_policies(self) -> list:
        if self._access_policies is None:
            try:
                data = self.session._config_get(
                    "policy/accesspolicies",
                    params={"expanded": "true", "limit": 1000},
                )
                self._access_policies = data.get("items", [])
            except Exception:
                self._access_policies = []
        return self._access_policies

    def _get_scheduled_tasks(self) -> list:
        if self._scheduled_tasks is None:
            try:
                self._scheduled_tasks = self.session._platform_get_paged("scheduledtasks")
            except Exception:
                self._scheduled_tasks = []
        return self._scheduled_tasks

    def _get_ssl_policies(self) -> list:
        if self._ssl_policies is None:
            try:
                self._ssl_policies = self.session._config_get_paged("policy/sslpolicies")
            except Exception:
                self._ssl_policies = []
        return self._ssl_policies

    def _get_intrusion_policies(self) -> list:
        if self._intrusion_policies is None:
            try:
                self._intrusion_policies = self.session._config_get_paged(
                    "policy/intrusionpolicies"
                )
            except Exception:
                self._intrusion_policies = []
        return self._intrusion_policies

    def _get_identity_policies(self) -> list:
        if self._identity_policies is None:
            try:
                self._identity_policies = self.session._config_get_paged(
                    "policy/identitypolicies"
                )
            except Exception:
                self._identity_policies = []
        return self._identity_policies

    def _get_realms(self) -> list:
        if self._realms is None:
            try:
                self._realms = self.session._config_get_paged("realm")
            except Exception:
                self._realms = []
        return self._realms

    def _has_scheduled_task(self, keywords: list[str]) -> tuple[bool, str]:
        """Return (found, evidence) — case-insensitive keyword match on jobType or name."""
        tasks = self._get_scheduled_tasks()
        if not tasks:
            return False, "No scheduled tasks found"
        kw_upper = [k.upper() for k in keywords]
        matches  = []
        for t in tasks:
            job_type = str(t.get("jobType", t.get("type", ""))).upper()
            name     = str(t.get("name", "")).upper()
            if any(k in job_type or k in name for k in kw_upper):
                matches.append(
                    f"{t.get('name','unnamed')} (type={job_type})"
                )
        if matches:
            return True, "; ".join(matches)
        return False, f"No match in {len(tasks)} scheduled task(s)"

    # ── run_all ──────────────────────────────────────────────────────────────

    def run_all(self, level_filter: str = "all") -> list[dict]:
        checks = [
            # § 1 Management Plane
            self._check_1_1_1_1, self._check_1_1_1_2,
            self._check_1_1_2,   self._check_1_1_3,
            self._check_1_1_4_1_1, self._check_1_1_4_1_2, self._check_1_1_4_1_3,
            self._check_1_1_4_1_4, self._check_1_1_4_1_5,
            self._check_1_1_4_1_6, self._check_1_1_4_1_7,
            self._check_1_2_1,
            self._check_1_3_1, self._check_1_3_2, self._check_1_3_3,
            self._check_1_3_4, self._check_1_3_5,
            self._check_1_4_1,
            self._check_1_4_2_1, self._check_1_4_2_2, self._check_1_4_2_3,
            self._check_1_4_2_4, self._check_1_4_2_5, self._check_1_4_2_6,
            self._check_1_4_3,
            self._check_1_5_1,
            self._check_1_6_1,
            # § 2 Data Plane
            self._check_2_1_1,  self._check_2_1_2,  self._check_2_1_3,
            self._check_2_1_4,  self._check_2_1_5,  self._check_2_1_6,
            self._check_2_1_7,  self._check_2_1_8,  self._check_2_1_9,
            self._check_2_1_10,
            # § 3 Control Plane
            self._check_3_1_1, self._check_3_1_2,
            self._check_3_2_1, self._check_3_2_2,
            self._check_3_3,
            # Additive (not in CIS benchmark)
            self._check_ver_1,
            self._check_ha_1,
        ]
        for fn in checks:
            try:
                result = fn()
                if result:
                    self._add(result)
            except Exception as e:
                cid = fn.__name__.replace("_check_", "").replace("_", ".", 5)
                self._add(make_result(cid, f"Check {cid}", "L1", ERROR,
                                      notes=f"Unhandled exception: {e}"))
        return self.results

    # =========================================================================
    # § 1  Management Plane
    # =========================================================================

    # 1.1.1 ── Access Management ──────────────────────────────────────────────

    def _check_1_1_1_1(self):
        return make_result(
            "1.1.1.1",
            "Ensure Multi-Factor Authentication is configured for admin access",
            "L1", MANUAL,
            guidance=(
                "1. System > Users > Users — for each admin, verify MFA is enforced\n"
                "2. System > Integration > Identity Sources — verify RADIUS/SSO with MFA\n"
                "3. If using SSO (SAML), confirm the IdP enforces MFA before granting access"
            ),
            remediation="Configure RADIUS-based MFA or integrate a SAML IdP that enforces MFA.",
        )

    def _check_1_1_1_2(self):
        return make_result(
            "1.1.1.2",
            "Ensure the default admin account is renamed or disabled",
            "L1", MANUAL,
            guidance=(
                "1. System > Users > Users — look for user named 'admin'\n"
                "2. Create a named replacement admin (firstname.lastname) before disabling\n"
                "3. Restrict the built-in 'admin' to break-glass use only\n"
                "Note: FMC cannot rename the built-in admin — restrict its use instead."
            ),
            remediation=(
                "Create a named admin account, verify access, then restrict or "
                "document the built-in 'admin' account for emergency use only."
            ),
        )

    def _check_1_1_2(self):
        """Local admin accounts minimized — Automated."""
        try:
            users = self.session._config_get_paged("users")
        except Exception as e:
            return make_result("1.1.2",
                               "Ensure local admin accounts are minimized",
                               "L1", ERROR, notes=f"API call failed: {e}")

        local_admins = [
            u for u in users
            if u.get("authenticationMethod", "").upper() == "LOCAL"
            and "admin" in u.get("userRole", {}).get("name", "").lower()
        ]
        names    = [u.get("username", u.get("name", "?")) for u in local_admins]
        evidence = f"Total users: {len(users)}. Local admins: {names}"

        if len(local_admins) > 2:
            return make_result(
                "1.1.2", "Ensure local admin accounts are minimized",
                "L1", FAIL,
                expected="≤2 local administrator accounts",
                actual=f"{len(local_admins)} local admin accounts: {names}",
                remediation=(
                    "Remove or convert to external authentication any local admin accounts "
                    "beyond the minimum needed for break-glass access."
                ),
                notes=evidence,
                risk_description="Excess local admin accounts multiply credential compromise risk.",
                default_risk_level="Medium",
            )
        return make_result("1.1.2", "Ensure local admin accounts are minimized",
                           "L1", PASS, actual=f"{len(local_admins)} local admin(s)", notes=evidence)

    def _check_1_1_3(self):
        """RBAC configured — Automated."""
        try:
            roles = self.session._config_get_paged("userroles")
        except Exception as e:
            return make_result("1.1.3",
                               "Ensure role-based access control (RBAC) is configured",
                               "L1", ERROR, notes=f"API call failed: {e}")

        custom = [r for r in roles if not r.get("system", True)]
        names  = [r.get("name", "?") for r in roles]
        if custom:
            return make_result(
                "1.1.3", "Ensure role-based access control (RBAC) is configured",
                "L1", PASS, actual=f"{len(custom)} custom role(s): {[r['name'] for r in custom]}",
                notes=f"All roles: {names}")
        if len(roles) >= 3:
            return make_result(
                "1.1.3", "Ensure role-based access control (RBAC) is configured",
                "L1", PASS, actual=f"{len(roles)} built-in roles; verify least-privilege assignments",
                notes=f"Roles: {names}")
        return make_result(
            "1.1.3", "Ensure role-based access control (RBAC) is configured",
            "L1", FAIL,
            expected="Multiple roles in use with least-privilege assignments",
            actual=f"Only {len(roles)} role(s); RBAC may not be configured",
            remediation="System > Users > User Roles > Create Role. Define custom roles per function.",
            notes=f"Roles: {names}",
            risk_description="Without RBAC all admins share maximum privilege, violating least privilege.",
            default_risk_level="Medium",
        )

    # 1.1.4.1 ── Identity / Realm ─────────────────────────────────────────────

    def _check_1_1_4_1_1(self):
        """Realm configured — Automated."""
        realms = self._get_realms()
        if realms:
            return make_result(
                "1.1.4.1.1", "Ensure an identity realm is configured",
                "L1", PASS, actual=f"{len(realms)} realm(s): {[r.get('name','?') for r in realms]}")
        return make_result(
            "1.1.4.1.1", "Ensure an identity realm is configured",
            "L1", FAIL,
            expected="At least one AD/LDAP realm",
            actual="No realms configured",
            remediation="Integration > Other Integrations > Realms > Add Realm. Configure AD/LDAP.",
            risk_description="Without an identity realm, user-based policies cannot be enforced.",
            default_risk_level="High",
        )

    def _check_1_1_4_1_2(self):
        """Realm directory configured — Automated."""
        realms = self._get_realms()
        if not realms:
            return make_result(
                "1.1.4.1.2", "Ensure realm directory server settings are configured",
                "L1", FAIL,
                expected="Realm with directory server configured", actual="No realms exist",
                remediation="Integration > Other Integrations > Realms > Add Realm.",
                risk_description="No identity source means no user-based policy enforcement.",
                default_risk_level="High",
            )
        missing = [r.get("name","?") for r in realms
                   if not r.get("directorySetting") and r.get("type","") not in ("AD","LDAP")]
        if missing:
            return make_result(
                "1.1.4.1.2", "Ensure realm directory server settings are configured",
                "L1", FAIL,
                expected="All realms have directory settings",
                actual=f"Realms missing directory settings: {missing}",
                remediation="Edit each realm and configure Directory Server settings.",
                notes=f"All realms: {[r.get('name') for r in realms]}",
                risk_description="Realms without directory settings cannot authenticate users.",
                default_risk_level="Medium",
            )
        return make_result(
            "1.1.4.1.2", "Ensure realm directory server settings are configured",
            "L1", PASS, actual=f"{len(realms)} realm(s) with directory settings configured")

    def _check_1_1_4_1_3(self):
        """Identity policy assigned — Automated."""
        policies = self._get_identity_policies()
        if not policies:
            return make_result(
                "1.1.4.1.3", "Ensure identity policies are configured and assigned",
                "L1", FAIL,
                expected="At least one identity policy", actual="No identity policies found",
                remediation="Policies > Access Control > Identity. Create an Identity Policy.",
                risk_description="Without identity policies, user-based access control is impossible.",
                default_risk_level="High",
            )
        access = self._get_access_policies()
        assigned = [ap.get("name","?") for ap in access
                    if ap.get("identityPolicySetting", {}).get("id")]
        names = [p.get("name","?") for p in policies]
        if assigned:
            return make_result(
                "1.1.4.1.3", "Ensure identity policies are configured and assigned",
                "L1", PASS,
                actual=f"{len(policies)} policy(ies) exist; assigned to: {assigned}",
                notes=f"Identity policies: {names}")
        return make_result(
            "1.1.4.1.3", "Ensure identity policies are configured and assigned",
            "L1", FAIL,
            expected="Identity policy assigned to at least one access policy",
            actual=f"{len(policies)} identity policy(ies) exist but none assigned",
            remediation="Policies > Access Control > [Policy] > Identity Policy tab. Assign policy.",
            notes=f"Identity policies: {names}",
            risk_description="Unassigned identity policies do not enforce user-based access control.",
            default_risk_level="Medium",
        )

    def _check_1_1_4_1_4(self):
        return make_result(
            "1.1.4.1.4", "Manage a Realm — verify realm management procedures", "L1", MANUAL,
            guidance=(
                "1. FMC > Integration > Other Integrations > Realms\n"
                "2. Verify all realms are expected and active\n"
                "3. Remove stale or test realms\n"
                "4. Verify realm state (enabled/disabled) matches operational requirements"
            ),
            remediation="Remove unused realms. Document realm configurations in the security baseline.",
        )

    def _check_1_1_4_1_5(self):
        return make_result(
            "1.1.4.1.5", "Compare Realms — verify realm drift detection is performed", "L1", MANUAL,
            guidance=(
                "1. Integration > Other Integrations > Realms > Compare Realms\n"
                "2. Compare production realm against documented baseline\n"
                "3. Investigate any unexpected differences and update baseline if change was authorised"
            ),
            remediation="Document the expected realm configuration. Perform periodic comparison.",
        )

    def _check_1_1_4_1_6(self):
        return make_result(
            "1.1.4.1.6", "Manage an Identity Policy — verify policy management procedures",
            "L1", MANUAL,
            guidance=(
                "1. Policies > Access Control > Identity\n"
                "2. Verify policies reflect current user access control requirements\n"
                "3. In multidomain deployments: verify domain-specific vs ancestor policies"
            ),
            remediation="Review all identity policies. Remove stale policies and document rule intent.",
        )

    def _check_1_1_4_1_7(self):
        return make_result(
            "1.1.4.1.7", "Manage an Identity Rule — verify rules within identity policies",
            "L1", MANUAL,
            guidance=(
                "1. Policies > Access Control > Identity > [Policy] > Edit\n"
                "2. Review each rule: realm, authentication type, zones\n"
                "3. Confirm no rules bypass authentication or reference decommissioned realms"
            ),
            remediation="Remove rules referencing old realms. Document each rule's business justification.",
        )

    # 1.2 ── Backups ──────────────────────────────────────────────────────────

    def _check_1_2_1(self):
        """Periodic FMC backups configured — Automated."""
        tasks = self._get_scheduled_tasks()
        backup_kw = ["BACKUP", "FMC_BACKUP", "MANAGEMENTCENTERBACKUP"]
        backup_tasks = [
            t for t in tasks
            if any(k in str(t.get("jobType", t.get("type",""))).upper() for k in backup_kw)
            or "backup" in str(t.get("name","")).lower()
        ]
        if not backup_tasks:
            return make_result(
                "1.2.1", "Create Periodic Backups of Firepower Management Center",
                "L1", FAIL,
                expected="Recurring backup task with remote copy",
                actual="No backup tasks found",
                remediation=(
                    "System > Scheduling > Add Task > Job Type: Backup > Recurring. "
                    "In Backup Profiles, enable 'Copy when complete' with SCP/SFTP remote host."
                ),
                notes=f"Total scheduled tasks: {len(tasks)}",
                risk_description="Without backups the FMC config cannot be recovered after failure.",
                default_risk_level="High",
            )
        has_remote = any(
            t.get("copyWhenComplete") or
            str(t.get("storageType","")).upper() not in ("LOCAL","")
            for t in backup_tasks
        )
        names = [t.get("name","?") for t in backup_tasks]
        if not has_remote:
            return make_result(
                "1.2.1", "Create Periodic Backups of Firepower Management Center",
                "L1", FAIL,
                expected="Backup tasks with remote (off-device) copy",
                actual=f"Backup task(s) found but stored locally only: {names}",
                remediation=(
                    "System > Backup/Restore > Backup Profiles. "
                    "Enable 'Copy when complete' and configure SCP/SFTP remote host."
                ),
                notes=f"Backup tasks: {names}",
                risk_description="Local-only backups are unavailable if the FMC server itself fails.",
                default_risk_level="Medium",
            )
        return make_result(
            "1.2.1", "Create Periodic Backups of Firepower Management Center",
            "L1", PASS, actual=f"{len(backup_tasks)} backup task(s) with remote copy: {names}")

    # 1.3 ── Scheduled Updates ────────────────────────────────────────────────

    def _check_update(self, cid, desc, keywords, update_type):
        found, ev = self._has_scheduled_task(keywords)
        if found:
            return make_result(cid, desc, "L1", PASS,
                               actual=f"Scheduled {update_type} task found", notes=ev)
        return make_result(
            cid, desc, "L1", FAIL,
            expected=f"Recurring {update_type} update task",
            actual=f"No {update_type} task found",
            remediation=f"System > Scheduling > Add Task > Job Type: {update_type} Update.",
            notes=ev,
            risk_description=f"Without automated {update_type} updates, new threats are not detected.",
            default_risk_level="High",
        )

    def _check_1_3_1(self):
        return self._check_update(
            "1.3.1", "Ensure Intrusion Rule Updates are scheduled",
            ["RULESDOWNLOAD","RULEUPDATE","RULEUPDATES","SNORT",
             "RULE UPDATE","INTRUSION RULE","SNORT UPDATE"], "Intrusion Rule")

    def _check_1_3_2(self):
        return self._check_update(
            "1.3.2", "Ensure Geolocation Database updates are scheduled",
            ["GEOLOCATION","GEOIP","GEO UPDATE","GEOLOCATION UPDATE"], "Geolocation")

    def _check_1_3_3(self):
        return self._check_update(
            "1.3.3", "Ensure URL Filtering Database updates are scheduled",
            ["URLDB","URLFILTERING","URL UPDATE","URL FILTER"], "URL Filtering")

    def _check_1_3_4(self):
        return self._check_update(
            "1.3.4", "Ensure Vulnerability Database (VDB) updates are scheduled",
            ["VDB","VDBUPDATE","VULNERABILITY DATABASE","VULNERABILITY UPDATE"], "VDB")

    def _check_1_3_5(self):
        return self._check_update(
            "1.3.5", "Ensure Security Intelligence / Malware Database updates are scheduled",
            ["SECURITYINTELLIGENCE","MALWARE","THREATDATA","AMP",
             "SECURITY INTELLIGENCE","MALWARE UPDATE"], "Security Intelligence")

    # 1.4 ── Health, Logging & Monitoring ─────────────────────────────────────

    def _check_1_4_1(self):
        """Health Policy assigned to all devices — Automated."""
        policies = self._get_health_policies()
        if not policies:
            return make_result(
                "1.4.1", "Ensure a Health Policy is assigned to all managed devices",
                "L1", FAIL,
                expected="Health Policy configured and assigned",
                actual="No Health Policies found",
                remediation="System > Health > Policy. Create and assign to all devices.",
                risk_description="No health monitoring — device failures may go undetected.",
                default_risk_level="Medium",
            )
        assigned = [p for p in policies if p.get("monitoringDevices")]
        names    = [p.get("name","?") for p in policies]
        if assigned:
            return make_result(
                "1.4.1", "Ensure a Health Policy is assigned to all managed devices",
                "L1", PASS,
                actual=f"{len(assigned)}/{len(policies)} health policy(ies) assigned to devices",
                notes=f"Policies: {names}")
        return make_result(
            "1.4.1", "Ensure a Health Policy is assigned to all managed devices",
            "L1", FAIL,
            expected="Health policy assigned to managed devices",
            actual=f"Health policies exist ({names}) but none assigned",
            remediation="System > Health > Policy > Apply. Select all managed devices.",
            risk_description="Unassigned health policies provide no device monitoring coverage.",
            default_risk_level="Medium",
        )

    def _check_1_4_2_1(self):
        """Syslog server configured in Platform Settings — Automated."""
        detail = self._get_first_platform_policy_detail()
        if not detail:
            return make_result(
                "1.4.2.1", "Ensure syslog server is configured in Platform Settings Policy",
                "L1", FAIL,
                expected="Platform Settings Policy with syslog server",
                actual="No Platform Settings Policy found",
                remediation="Devices > Platform Settings. Create FTD policy, add Syslog servers.",
                risk_description="Security events not forwarded to SIEM for correlation.",
                default_risk_level="High",
            )
        syslog = detail.get("syslogSettings", detail.get("syslog", {}))
        servers = syslog.get("servers", syslog.get("syslogServers", []))
        pname   = detail.get("name","?")
        if servers:
            ips = [s.get("ip", s.get("host", s.get("name","?"))) for s in servers]
            return make_result(
                "1.4.2.1", "Ensure syslog server is configured in Platform Settings Policy",
                "L1", PASS, actual=f"{len(servers)} syslog server(s): {ips}",
                notes=f"Policy: {pname}")
        return make_result(
            "1.4.2.1", "Ensure syslog server is configured in Platform Settings Policy",
            "L1", FAIL,
            expected="At least one syslog server configured",
            actual=f"No syslog servers in policy '{pname}'",
            remediation="Devices > Platform Settings > [Policy] > Syslog > Syslog Servers > Add.",
            notes=f"Policy: {pname}",
            risk_description="Events not sent to SIEM — no external log retention.",
            default_risk_level="High",
        )

    def _check_1_4_2_2(self):
        """FMC event logging — surfaced as Manual since it spans multiple policy layers."""
        detail = self._get_first_platform_policy_detail()
        pname  = detail.get("name","?") if detail else "none"
        return make_result(
            "1.4.2.2", "Ensure connection events are logged to the FMC Events Database",
            "L1", MANUAL,
            guidance=(
                "1. Devices > Platform Settings > [Policy] > Syslog > Syslog Settings — "
                "verify 'Send Syslog Messages' is enabled\n"
                "2. Policies > Access Control > [Policy] > Default Action > Logging — "
                "verify 'Log to FMC Events Database' (Event Viewer) is enabled\n"
                "3. Repeat for each allow/trust rule in all access policies"
            ),
            notes=f"Platform Settings Policy found: {pname}",
        )

    def _check_1_4_2_3(self):
        """Time Synchronisation health module ON — Automated."""
        policies = self._get_health_policies()
        if not policies:
            return make_result(
                "1.4.2.3",
                "Ensure Health Policy has Time Synchronization Status module enabled",
                "L1", FAIL,
                expected="Health policy with Time Synchronization module enabled",
                actual="No health policies found",
                remediation="Create a health policy and enable the Time Synchronization module.",
                risk_description="NTP drift not monitored — log timestamps may be unreliable.",
                default_risk_level="Medium",
            )
        for policy in policies:
            pid = policy.get("id","")
            if not pid:
                continue
            try:
                detail  = self.session._config_get(f"policy/healthpolicies/{pid}")
            except Exception:
                continue
            modules = detail.get("healthModules", detail.get("modules", []))
            for mod in modules:
                mname = str(mod.get("moduleName", mod.get("name",""))).lower()
                if "time" in mname and ("sync" in mname or "synchroni" in mname):
                    enabled = mod.get("enabled", mod.get("status", False))
                    ev = (f"Policy: {policy.get('name','?')}; "
                          f"module: {mod.get('moduleName',mod.get('name','?'))}; "
                          f"enabled: {enabled}")
                    if enabled:
                        return make_result(
                            "1.4.2.3",
                            "Ensure Health Policy has Time Synchronization Status module enabled",
                            "L1", PASS, actual="Time Synchronization module enabled", notes=ev)
                    return make_result(
                        "1.4.2.3",
                        "Ensure Health Policy has Time Synchronization Status module enabled",
                        "L1", FAIL,
                        expected="Time Synchronization module enabled",
                        actual="Module found but disabled",
                        remediation="System > Health > Policy > [Policy] > Enable Time Synchronization module.",
                        notes=ev,
                        risk_description="NTP drift not monitored — timestamps unreliable for forensics.",
                        default_risk_level="Medium",
                    )
        return make_result(
            "1.4.2.3",
            "Ensure Health Policy has Time Synchronization Status module enabled",
            "L1", FAIL,
            expected="Time Synchronization module enabled",
            actual="Module not found in any health policy (disabled by default)",
            remediation="System > Health > Policy > [Policy] > Enable Time Synchronization Status module.",
            notes=f"Checked {len(policies)} health policy(ies)",
            risk_description="NTP drift not monitored — log timestamps may be unreliable.",
            default_risk_level="Medium",
        )

    def _check_1_4_2_4(self):
        """SSH access list configured — Automated."""
        detail = self._get_first_platform_policy_detail()
        pname  = detail.get("name","?") if detail else "none"
        if not detail:
            return make_result(
                "1.4.2.4", "Ensure SSH management access list is configured",
                "L1", FAIL,
                expected="Platform Settings Policy with SSH access list",
                actual="No Platform Settings Policy found",
                remediation="Create Platform Settings Policy with SSH access list restricted to management hosts.",
                risk_description="Any host can attempt SSH to managed devices.",
                default_risk_level="High",
            )
        ssh  = detail.get("sshSettings", detail.get("SSHTimeouts", {}))
        acl  = ssh.get("accessList", ssh.get("allowedHosts", []))
        if acl:
            return make_result(
                "1.4.2.4", "Ensure SSH management access list is configured",
                "L1", PASS, actual=f"SSH access list with {len(acl)} entry(ies)",
                notes=f"Policy: {pname}; entries: {acl[:5]}")
        return make_result(
            "1.4.2.4", "Ensure SSH management access list is configured",
            "L1", FAIL,
            expected="SSH access list with specific management IPs",
            actual=f"No SSH access list in policy '{pname}'",
            remediation="Devices > Platform Settings > [Policy] > SSH Access. Add management IP ranges.",
            notes=f"Policy: {pname}",
            risk_description="Unrestricted SSH enables brute-force attacks from any host.",
            default_risk_level="High",
        )

    def _check_1_4_2_5(self):
        """HTTPS management access list configured — Automated."""
        detail = self._get_first_platform_policy_detail()
        pname  = detail.get("name","?") if detail else "none"
        if not detail:
            return make_result(
                "1.4.2.5", "Ensure HTTPS management access list is configured",
                "L1", FAIL,
                expected="Platform Settings Policy with HTTPS access list",
                actual="No Platform Settings Policy found",
                remediation="Create Platform Settings Policy with HTTPS access list.",
                risk_description="FMC web UI accessible from any network.",
                default_risk_level="High",
            )
        https = detail.get("httpsSettings", detail.get("HTTPSCertificates", {}))
        acl   = https.get("accessList", https.get("allowedHosts", []))
        if acl:
            return make_result(
                "1.4.2.5", "Ensure HTTPS management access list is configured",
                "L1", PASS, actual=f"HTTPS access list with {len(acl)} entry(ies)",
                notes=f"Policy: {pname}; entries: {acl[:5]}")
        return make_result(
            "1.4.2.5", "Ensure HTTPS management access list is configured",
            "L1", FAIL,
            expected="HTTPS access list with specific management IPs",
            actual=f"No HTTPS access list in policy '{pname}'",
            remediation="Devices > Platform Settings > [Policy] > HTTP Access. Add management IPs.",
            notes=f"Policy: {pname}",
            risk_description="Unrestricted HTTPS exposes FMC web interface to attack.",
            default_risk_level="High",
        )

    def _check_1_4_2_6(self):
        return make_result(
            "1.4.2.6", "Ensure audit logs are sent to an external syslog server",
            "L1", MANUAL,
            guidance=(
                "1. System > Configuration > Audit Log\n"
                "2. Enable 'Send Audit Log to Syslog'\n"
                "3. Configure syslog host IP, port (UDP 514 default), and facility\n"
                "4. Verify audit events (logins, config changes) appear in the syslog server"
            ),
            remediation=(
                "System > Configuration > Audit Log. Enable 'Send Audit Log to Syslog'. "
                "Configure syslog host. This ensures admin actions are retained externally."
            ),
        )

    def _check_1_4_3(self):
        """SNMP v3 only — Automated."""
        detail = self._get_first_platform_policy_detail()
        if not detail:
            return make_result(
                "1.4.3", "Ensure SNMP v3 is used and SNMP v1/v2c are disabled",
                "L2", FAIL,
                expected="SNMP v3 configured; v1/v2c disabled",
                actual="No Platform Settings Policy found",
                remediation="Create Platform Settings Policy with SNMP v3 users only.",
                risk_description="SNMP v1/v2c community strings transmitted in cleartext.",
                default_risk_level="High",
            )
        snmp = detail.get("snmpConfig", detail.get("snmpSettings", {}))
        if not snmp:
            return make_result(
                "1.4.3", "Ensure SNMP v3 is used and SNMP v1/v2c are disabled",
                "L2", MANUAL,
                guidance=(
                    "Devices > Platform Settings > [Policy] > SNMP.\n"
                    "Verify: no v1/v2c communities; v3 users configured with AuthPriv."
                ),
                notes=f"Policy '{detail.get('name','?')}' SNMP section not readable via API.")
        communities = snmp.get("communities", snmp.get("v1v2Communities", []))
        v3_users    = snmp.get("users", snmp.get("v3Users", []))
        evidence    = f"v1/v2c communities: {len(communities)}; v3 users: {len(v3_users)}"
        if communities:
            names = [c.get("communityString", c.get("name","?")) for c in communities]
            return make_result(
                "1.4.3", "Ensure SNMP v3 is used and SNMP v1/v2c are disabled",
                "L2", FAIL,
                expected="No v1/v2c communities; v3 only",
                actual=f"SNMP v1/v2c communities found: {names}",
                remediation="Platform Settings > [Policy] > SNMP. Remove all v1/v2c communities.",
                notes=evidence,
                risk_description="SNMP v1/v2c community strings can be sniffed in cleartext.",
                default_risk_level="High",
            )
        if not v3_users:
            return make_result(
                "1.4.3", "Ensure SNMP v3 is used and SNMP v1/v2c are disabled",
                "L2", FAIL,
                expected="SNMP v3 users configured (or SNMP fully disabled)",
                actual="No SNMP config — verify whether SNMP is required",
                remediation="If SNMP monitoring required, configure v3 users only.",
                notes=evidence)
        return make_result(
            "1.4.3", "Ensure SNMP v3 is used and SNMP v1/v2c are disabled",
            "L2", PASS, actual=f"{len(v3_users)} SNMP v3 user(s); no v1/v2c", notes=evidence)

    # 1.5 ── Nmap ─────────────────────────────────────────────────────────────

    def _check_1_5_1(self):
        found, ev = self._has_scheduled_task(
            ["NMAP","NMAPREMEDIATIONSCAN","NMAP SCAN","NMAP REMEDIATION"])
        if found:
            return make_result("1.5.1", "Ensure Nmap remediation scans are scheduled",
                               "L1", PASS, actual="Nmap scan task found", notes=ev)
        return make_result(
            "1.5.1", "Ensure Nmap remediation scans are scheduled",
            "L1", FAIL,
            expected="Recurring Nmap scan task",
            actual="No Nmap tasks found",
            remediation="System > Scheduling > Add Task > Job Type: Nmap Scan.",
            notes=ev,
            risk_description="Unknown hosts on monitored segments remain undiscovered.",
            default_risk_level="Medium",
        )

    # 1.6 ── Vulnerability Database ───────────────────────────────────────────

    def _check_1_6_1(self):
        """VDB currency — Automated."""
        try:
            data = self.session._platform_get("updates/latestintrusionstates")
        except Exception as e:
            return make_result("1.6.1", "Ensure Vulnerability Database (VDB) is current",
                               "L1", ERROR, notes=f"API call failed: {e}")
        last_update = data.get("lastUpdate", data.get("updateTime",""))
        vdb_version = data.get("vdbVersion", data.get("version",""))
        evidence    = f"VDB version: {vdb_version}; last update: {last_update}"
        if not last_update:
            return make_result("1.6.1", "Ensure Vulnerability Database (VDB) is current",
                               "L1", MANUAL,
                               guidance="System > Updates. Compare VDB version against latest on Cisco's support site.",
                               notes=evidence)
        try:
            raw = last_update[:19].rstrip("Z")
            update_dt = datetime.datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S")
            days      = (datetime.datetime.utcnow() - update_dt).days
            if days > 30:
                return make_result(
                    "1.6.1", "Ensure Vulnerability Database (VDB) is current",
                    "L1", FAIL,
                    expected="VDB updated within 30 days",
                    actual=f"VDB last updated {days} days ago",
                    remediation="System > Updates > Vulnerability and Fingerprint Updates > Download and Install.",
                    notes=evidence,
                    risk_description="Outdated VDB — newly discovered vulnerabilities not detected.",
                    default_risk_level="High",
                )
            return make_result(
                "1.6.1", "Ensure Vulnerability Database (VDB) is current",
                "L1", PASS, actual=f"VDB updated {days} days ago", notes=evidence)
        except Exception:
            return make_result("1.6.1", "Ensure Vulnerability Database (VDB) is current",
                               "L1", MANUAL,
                               guidance="System > Updates. Verify VDB date manually.",
                               notes=evidence)

    # =========================================================================
    # § 2  Data Plane
    # =========================================================================

    def _check_2_1_1(self):
        """Access Policy default action logging — API-checkable Manual."""
        policies = self._get_access_policies()
        if not policies:
            return make_result(
                "2.1.1", "Ensure Access Policy default action has logging configured",
                "L1", FAIL,
                expected="Access Policy with default action logging",
                actual="No access policies found",
                remediation="Policies > Access Control. Create Access Policy with logging configured.",
                risk_description="No traffic logging — no visibility into network activity.",
                default_risk_level="High",
            )
        failing = []
        for p in policies:
            da      = p.get("defaultAction", {})
            issues  = []
            if str(da.get("logBegin","")).upper() not in ("TRUE","1"):
                issues.append("logBegin not TRUE")
            if str(da.get("logEnd","")).upper() not in ("TRUE","1"):
                issues.append("logEnd not TRUE")
            if str(da.get("sendEventsToFMC","")).upper() not in ("TRUE","1"):
                issues.append("sendEventsToFMC not TRUE")
            syslog = da.get("syslogConfig", {})
            if not syslog or syslog.get("name","") == "UNDEFINED":
                issues.append("syslogConfig not set")
            if issues:
                failing.append(f"{p.get('name','?')}: {'; '.join(issues)}")
        if failing:
            return make_result(
                "2.1.1", "Ensure Access Policy default action has logging configured",
                "L1", FAIL,
                expected="logBegin=TRUE, logEnd=TRUE, sendEventsToFMC=TRUE, syslog configured",
                actual=f"{len(failing)} policy(ies) with logging gaps: {failing[:3]}",
                remediation=(
                    "Policies > Access Control > [Policy] > Default Action > Logging. "
                    "Enable Log at Beginning/End of Connection. "
                    "Under Sending: enable FMC and select a Syslog Server."
                ),
                notes=f"Checked {len(policies)} policy(ies)",
                risk_description="Default-action traffic not logged — blind spots in visibility.",
                default_risk_level="High",
            )
        return make_result(
            "2.1.1", "Ensure Access Policy default action has logging configured",
            "L1", PASS,
            actual=f"All {len(policies)} policy(ies) have default action logging",
            notes=f"Policies: {[p.get('name','?') for p in policies]}")

    def _check_2_1_2(self):
        return make_result(
            "2.1.2", "Create an outbound SSL Policy — verify SSL decryption is documented",
            "L1", MANUAL,
            guidance=(
                "1. Policies > SSL — verify an SSL policy exists with Decrypt-Resign rules\n"
                "2. Verify at minimum these categories are 'Do Not Decrypt': Finance, "
                "Government and Law, Health and Medicine\n"
                "3. Policies > Access Control > [Policy] > SSL Policy — verify policy is assigned\n"
                "4. Confirm written org policy authorises decryption scope and users are informed"
            ),
            remediation=(
                "Create SSL policy with Decrypt-Resign rules. Apply Do Not Decrypt for Finance, "
                "Government/Law, Health categories. Assign SSL policy to Access Control Policy."
            ),
        )

    def _check_2_1_3(self):
        """IPS policy with base policy — Automated."""
        policies = self._get_intrusion_policies()
        if not policies:
            return make_result(
                "2.1.3", "Ensure an Intrusion Prevention Policy is configured",
                "L2", FAIL,
                expected="At least one IPS policy with base policy",
                actual="No intrusion policies found",
                remediation="Policies > Access Control > Intrusion. Create IPS policy with Balanced base.",
                risk_description="No IPS capability — attacks pass uninspected.",
                default_risk_level="High",
            )
        with_base = [p.get("name","?") for p in policies if p.get("basePolicy") or p.get("basePolicyName")]
        names     = [p.get("name","?") for p in policies]
        if with_base:
            return make_result(
                "2.1.3", "Ensure an Intrusion Prevention Policy is configured",
                "L2", PASS, actual=f"{len(with_base)} policy(ies) with base policy: {with_base}",
                notes=f"All policies: {names}")
        return make_result(
            "2.1.3", "Ensure an Intrusion Prevention Policy is configured",
            "L2", FAIL,
            expected="IPS policy with a base policy applied",
            actual=f"{len(policies)} policy(ies) found but none have a base policy",
            remediation="Policies > Intrusion > [Policy] > Base Policy. Select 'Balanced Security and Connectivity'.",
            notes=f"Policies: {names}",
            risk_description="IPS policy without a base policy may not detect known attack patterns.",
            default_risk_level="High",
        )

    def _check_2_1_4(self):
        """TLS Server Identity Discovery — Automated."""
        policies = self._get_access_policies()
        if not policies:
            return make_result(
                "2.1.4", "Ensure TLS Server Identity Discovery is enabled",
                "L1", FAIL,
                expected="Access policy with TLS Server Identity Discovery enabled",
                actual="No access policies found",
                remediation="Create access policy and enable TLS Server Identity Discovery in Advanced.",
                risk_description="Cannot verify TLS server identity — MitM risk.",
                default_risk_level="Medium",
            )
        failing = []
        for p in policies:
            adv = p.get("advancedSettings", {})
            tls = (adv.get("enableTlsServerIdentityDiscovery") or
                   adv.get("tlsServerIdentityDiscovery", {}).get("enable"))
            if not tls:
                failing.append(p.get("name","?"))
        if failing:
            return make_result(
                "2.1.4", "Ensure TLS Server Identity Discovery is enabled",
                "L1", FAIL,
                expected="TLS Server Identity Discovery enabled in all access policies",
                actual=f"{len(failing)} policy(ies) without TLS Identity Discovery: {failing}",
                remediation="Policies > Access Control > [Policy] > Advanced > check TLS Server Identity Discovery.",
                notes=f"Checked {len(policies)} policy(ies)",
                risk_description="Disabled TLS discovery prevents verification of TLS server authenticity.",
                default_risk_level="Medium",
            )
        return make_result(
            "2.1.4", "Ensure TLS Server Identity Discovery is enabled",
            "L1", PASS,
            actual=f"Enabled in all {len(policies)} policy(ies)",
            notes=f"Policies: {[p.get('name','?') for p in policies]}")

    def _check_2_1_5(self):
        return make_result(
            "2.1.5", "Access Policy File Policy — verify malware/file inspection is configured",
            "L1", MANUAL,
            guidance=(
                "1. Policies > Malware and File — verify at least one file policy exists\n"
                "2. Edit file policy: verify Block Malware rules for EXE, PDF, MSOFFICE, etc.\n"
                "3. Policies > Access Control > [Policy] — for each Allow rule verify File Policy assigned\n"
                "Default: no File Policy exists."
            ),
            remediation=(
                "Policies > Malware and File > New File Policy. Add Block Malware rules. "
                "Assign to all Permit rules in the Access Control Policy."
            ),
        )

    def _check_2_1_6(self):
        """SSL Decryption policy exists — Automated."""
        policies = self._get_ssl_policies()
        if policies:
            return make_result(
                "2.1.6", "Ensure SSL/TLS Decryption (SSL Policy) is enabled",
                "L2", PASS,
                actual=f"{len(policies)} SSL policy(ies): {[p.get('name','?') for p in policies]}")
        return make_result(
            "2.1.6", "Ensure SSL/TLS Decryption (SSL Policy) is enabled",
            "L2", FAIL,
            expected="At least one SSL decryption policy",
            actual="No SSL policies found — decryption not configured",
            remediation="Policies > SSL > New SSL Policy. Add Decrypt-Resign rules. Assign to Access Policy.",
            risk_description="Encrypted traffic cannot be inspected for malware or data exfiltration.",
            default_risk_level="High",
        )

    def _check_2_1_7(self):
        return make_result(
            "2.1.7", "Access Policy — URL Filtering: verify category-based blocking",
            "L1", MANUAL,
            guidance=(
                "1. Policies > Access Control > [Policy]\n"
                "2. Verify 'block by category' rules exist for at minimum:\n"
                "   IT: Botnets, Hacking, Malware Sites, Spyware and Adware\n"
                "   HR: Pornography, Illegal Downloads, Terrorism\n"
                "3. Verify a written URL filtering policy exists and users have been informed\n"
                "Default: no block-by-category rules."
            ),
            remediation="Add URL category block rules to Access Control Policy with logging enabled.",
        )

    def _check_2_1_8(self):
        return make_result(
            "2.1.8", "Enable secure VPN AnyConnect tunnelling protocols",
            "L1", MANUAL,
            guidance=(
                "Devices > VPN > Remote Access (AnyConnect). For each VPN profile:\n"
                "- Encryption: AES-256 or AES-GCM-256\n"
                "- DH group: 20 or higher\n"
                "- Integrity: SHA-384 or SHA-512\n"
                "- PRF: SHA-384 or SHA-512\n"
                "Remove DES, 3DES, MD5, DH groups < 14."
            ),
            remediation="Update AnyConnect IKEv2 policies to AES-256/GCM-256, DH20+, SHA-384/512.",
        )

    def _check_2_1_9(self):
        return make_result(
            "2.1.9", "Enable secure Site-to-Site VPN tunnelling protocols",
            "L1", MANUAL,
            guidance=(
                "Devices > VPN > Site To Site. For each topology IKEv2 policy:\n"
                "- Encryption: AES-256 or AES-GCM-256\n"
                "- DH group: 20 or higher\n"
                "- Integrity: SHA-384 or SHA-512\n"
                "Default: Not Configured."
            ),
            remediation="Edit Site-to-Site VPN IKEv2 policies to use strong cipher suites.",
        )

    def _check_2_1_10(self):
        return make_result(
            "2.1.10", "Access Policy Application Settings — verify Application field used in rules",
            "L1", MANUAL,
            guidance=(
                "1. Policies > Access Control > [Policy]\n"
                "2. For each Permit/Allow rule > Applications tab\n"
                "3. Verify Application is not 'Any' where destination port is known\n"
                "Default: Application='Any' for all new rules."
            ),
            remediation="For rules with known destination ports, select specific applications to restrict matching.",
        )

    # =========================================================================
    # § 3  Control Plane
    # =========================================================================

    def _check_3_1_1(self):
        return make_result(
            "3.1.1", "Secure the Network Time Protocol (NTP) Server configuration",
            "L1", MANUAL,
            guidance=(
                "Devices > Platform Settings > [Policy] > Time Synchronization.\n"
                "Verify:\n"
                "1. At least two NTP servers configured\n"
                "2. NTP servers are trusted/internal (not public internet)\n"
                "3. NTP authentication configured where supported\n"
                "Default: 'Via NTP from Defense Center'."
            ),
            remediation=(
                "Devices > Platform Settings > [Policy] > Time Synchronization. "
                "Configure 'Via NTP from' with two+ trusted NTP servers."
            ),
        )

    def _check_3_1_2(self):
        return make_result(
            "3.1.2", "Secure the Domain Name System (DNS) configuration",
            "L1", MANUAL,
            guidance=(
                "Devices > Platform Settings > [Policy] > DNS > DNS Settings.\n"
                "Verify:\n"
                "1. DNS Server Groups use internal/trusted resolvers\n"
                "2. 'Enable DNS name resolution by device' is checked\n"
                "Default: no DNS setting configured."
            ),
            remediation="Configure DNS Server Groups with two+ internal DNS server IPs.",
        )

    def _check_3_2_1(self):
        """Fragment reassembly disabled (chain=1) — Automated."""
        detail = self._get_first_platform_policy_detail()
        if not detail:
            return make_result(
                "3.2.1", "Ensure fragment reassembly is disabled (Chain=1)",
                "L2", FAIL,
                expected="Platform Settings Policy with fragmentSettings.chain=1",
                actual="No Platform Settings Policy found",
                remediation="Devices > Platform Settings > FTD Policy > Fragment Settings > set Chain=1.",
                risk_description="Fragment chains allow IPS evasion via fragmented payloads.",
                default_risk_level="Medium",
            )
        frag = (detail.get("ftdPlatformSettings", {}).get("fragmentSettings") or
                detail.get("fragmentSettings") or {})
        chain = frag.get("chain")
        ev    = f"Policy: {detail.get('name','?')}; fragmentSettings: {frag}"
        if chain is None:
            return make_result(
                "3.2.1", "Ensure fragment reassembly is disabled (Chain=1)",
                "L2", MANUAL,
                guidance="Devices > Platform Settings > [FTD Policy] > Fragment Settings. Verify Chain=1.",
                notes=ev + " — API did not return fragment settings; verify manually.")
        if int(chain) == 1:
            return make_result(
                "3.2.1", "Ensure fragment reassembly is disabled (Chain=1)",
                "L2", PASS, actual=f"Chain={chain} (reassembly disabled)", notes=ev)
        return make_result(
            "3.2.1", "Ensure fragment reassembly is disabled (Chain=1)",
            "L2", FAIL,
            expected="fragmentSettings.chain = 1",
            actual=f"fragmentSettings.chain = {chain}",
            remediation="Devices > Platform Settings > [FTD Policy] > Fragment Settings > set Chain=1 > Save and Deploy.",
            notes=ev,
            risk_description="Multiple fragment chains allow attackers to evade IPS inspection.",
            default_risk_level="Medium",
        )

    def _check_3_2_2(self):
        """Block old TLS/SSL versions — Automated."""
        ssl_policies = self._get_ssl_policies()
        if not ssl_policies:
            return make_result(
                "3.2.2", "Ensure a rule blocks SSL v3.0 / TLS v1.0 / TLS v1.1",
                "L1", FAIL,
                expected="SSL policy with block rule for old TLS/SSL",
                actual="No SSL policies — old TLS versions not blocked",
                remediation=(
                    "Policies > Access Control > SSL > New SSL Policy. "
                    "Add rule: Action=Block; Version=SSL v3, TLS v1.0, TLS v1.1."
                ),
                risk_description="SSL v3/TLS 1.0/1.1 have known critical vulnerabilities (POODLE, BEAST).",
                default_risk_level="High",
            )
        OLD_TLS = {"SSL_V3","TLS_1_0","TLS_1_1","SSLV3","TLS10","TLS11","SSL3","TLS1.0","TLS1.1"}
        found = False
        for policy in ssl_policies:
            pid = policy.get("id","")
            if not pid:
                continue
            try:
                rules_data = self.session._config_get(
                    f"policy/sslrules", params={"policyId": pid, "limit": 1000}
                )
                if not rules_data.get("items"):
                    rules_data = self.session._config_get(
                        f"policy/sslpolicies/{pid}/sslrules",
                        params={"limit": 1000}
                    )
                rules = rules_data.get("items", [])
            except Exception:
                continue
            for rule in rules:
                action = str(rule.get("action","")).upper()
                if "BLOCK" not in action and "RESET" not in action:
                    continue
                ver_obj = rule.get("version", rule.get("versions", rule.get("tlsVersion", {})))
                if not ver_obj:
                    continue
                ver_strs = (ver_obj if isinstance(ver_obj, list)
                            else list(ver_obj.values()) if isinstance(ver_obj, dict)
                            else [str(ver_obj)])
                if any(str(v).upper().replace("-","_").replace(".","") in
                       {o.replace(".","").replace("-","_") for o in OLD_TLS}
                       for v in ver_strs):
                    found = True
                    break
            if found:
                break
        if found:
            return make_result(
                "3.2.2", "Ensure a rule blocks SSL v3.0 / TLS v1.0 / TLS v1.1",
                "L1", PASS, actual="SSL policy rule blocking old TLS/SSL versions found",
                notes=f"Checked: {[p.get('name','?') for p in ssl_policies]}")
        return make_result(
            "3.2.2", "Ensure a rule blocks SSL v3.0 / TLS v1.0 / TLS v1.1",
            "L1", FAIL,
            expected="SSL rule BLOCK targeting SSL v3/TLS 1.0/TLS 1.1",
            actual="No blocking rule for old TLS/SSL found",
            remediation="Policies > Access Control > SSL. Add Block rule for SSL v3, TLS 1.0, TLS 1.1.",
            notes=f"Policies checked: {[p.get('name','?') for p in ssl_policies]}",
            risk_description="SSL v3/TLS 1.0/1.1 are cryptographically broken (POODLE, BEAST).",
            default_risk_level="High",
        )

    def _check_3_3(self):
        """Default action = Block with logging — Automated."""
        policies = self._get_access_policies()
        if not policies:
            return make_result(
                "3.3", "Ensure Access Policy default action is Block",
                "L1", FAIL,
                expected="Access Policy with default action DENY/BLOCK and LOG_BOTH",
                actual="No access policies found",
                remediation="Create Access Control Policy with default action Block.",
                risk_description="No policy — all traffic disposition is undefined.",
                default_risk_level="High",
            )
        failing = []
        for p in policies:
            da         = p.get("defaultAction", {})
            action     = str(da.get("action","")).upper()
            log_action = str(da.get("eventLogAction", da.get("logAction",""))).upper()
            issues     = []
            if action not in ("DENY","BLOCK","BLOCK_RESET"):
                issues.append(f"action={da.get('action','?')} (expected DENY/BLOCK)")
            if "LOG" not in log_action:
                issues.append(f"eventLogAction={da.get('eventLogAction','?')} (expected LOG_BOTH)")
            if issues:
                failing.append(f"{p.get('name','?')}: {'; '.join(issues)}")
        if failing:
            return make_result(
                "3.3", "Ensure Access Policy default action is Block",
                "L1", FAIL,
                expected="defaultAction.action=DENY, eventLogAction=LOG_BOTH",
                actual=f"{len(failing)} policy(ies) non-compliant: {failing}",
                remediation=(
                    "Policies > Access Control > [Policy] > Default Action = 'Block All Traffic'. "
                    "Logging > Log at Beginning and End of Connection."
                ),
                notes=f"Checked {len(policies)} policy(ies)",
                risk_description="Non-blocking default action permits unmatched traffic — violates zero trust.",
                default_risk_level="High",
            )
        return make_result(
            "3.3", "Ensure Access Policy default action is Block",
            "L1", PASS,
            actual=f"All {len(policies)} policy(ies) have default action DENY/BLOCK with logging",
            notes=f"Policies: {[p.get('name','?') for p in policies]}")

    # =========================================================================
    # Additive checks — not in CIS benchmark; required for full posture picture
    # =========================================================================

    def _check_ver_1(self):
        """FMC software version and lifecycle risk — checks against _FMC_EOL table."""
        import re
        try:
            data = self.session._platform_get("info/serverversion")
        except Exception as e:
            return make_result(
                "VER-1", "FMC Software Version and Lifecycle Risk",
                "L1", ERROR, notes=f"API call failed: {e}")

        items = data.get("items", [])
        if not items:
            return make_result(
                "VER-1", "FMC Software Version and Lifecycle Risk",
                "L1", MANUAL,
                guidance=(
                    "System > Updates > FMC Software. Note the current version and compare "
                    "against Cisco's End-of-Life / End-of-Support table for FMC."
                ),
                notes="No version info returned by API")

        ver_str = items[0].get("serverVersion", "")
        m = re.match(r"(\d+)\.(\d+)", ver_str)
        if not m:
            return make_result(
                "VER-1", "FMC Software Version and Lifecycle Risk",
                "L1", MANUAL,
                guidance="System > Updates. Verify FMC version manually against Cisco EoL/EoS tables.",
                notes=f"Could not parse version string: '{ver_str}'")

        major, minor = int(m.group(1)), int(m.group(2))
        eol_entry    = _FMC_EOL.get((major, minor))

        if not eol_entry:
            return make_result(
                "VER-1", "FMC Software Version and Lifecycle Risk",
                "L1", MANUAL,
                guidance=(
                    "Verify this version against the Cisco FMC Software Lifecycle page: "
                    "https://www.cisco.com/c/en/us/products/collateral/security/firepower-management-center/"
                    "eos-eol-notice-c51-740917.html"
                ),
                notes=f"Version {ver_str} — no EOL data in local table (may be newer than table)")

        eosm_date, eos_date = eol_entry
        today   = datetime.datetime.utcnow().date()
        eos_dt  = datetime.datetime.strptime(eos_date,  "%Y-%m-%d").date()
        eosm_dt = datetime.datetime.strptime(eosm_date, "%Y-%m-%d").date()

        if today > eos_dt:
            return make_result(
                "VER-1", "FMC Software Version and Lifecycle Risk",
                "L1", FAIL,
                expected="Supported FMC version (within End of Support date)",
                actual=(
                    f"FMC {ver_str} — End of Support was {eos_date} "
                    f"(past by {(today - eos_dt).days} days)"
                ),
                remediation=(
                    "Upgrade FMC to a supported release. "
                    "Current supported branches: 7.4.x (EoS 2027-01-31) and 7.6.x (EoS 2029-07-31). "
                    "Consult Cisco's FMC upgrade guide and upgrade managed FTD devices afterwards."
                ),
                notes=f"Version: {ver_str}",
                risk_description=(
                    "Running an end-of-support FMC means no security patches are available, "
                    "leaving known CVEs permanently unmitigated."
                ),
                default_risk_level="High",
            )

        six_months = datetime.timedelta(days=180)
        if (eos_dt - today) <= six_months:
            return make_result(
                "VER-1", "FMC Software Version and Lifecycle Risk",
                "L1", RECOMMENDATION,
                expected="FMC version with >6 months of support remaining",
                actual=(
                    f"FMC {ver_str} — End of Support {eos_date} "
                    f"({(eos_dt - today).days} days remaining)"
                ),
                remediation=(
                    "Begin planning upgrade to FMC 7.4.x or 7.6.x before the End of Support date."
                ),
                notes=f"Version: {ver_str}; EOSM: {eosm_date}; EoS: {eos_date}",
                risk_description=(
                    "FMC approaching End of Support — plan upgrade to avoid unsupported operation."
                ),
                default_risk_level="Medium",
            )

        return make_result(
            "VER-1", "FMC Software Version and Lifecycle Risk",
            "L1", PASS,
            actual=f"FMC {ver_str} — supported until {eos_date}",
            notes=f"Version: {ver_str}; EOSM: {eosm_date}; EoS: {eos_date}")

    def _check_ha_1(self):
        """High Availability and Resilience — FTD HA pairs and clusters."""
        try:
            data  = self.session._config_get("devicehapairs/ftddevicehapairs")
            pairs = data.get("items", [])
        except Exception as e:
            return make_result(
                "HA-1", "High Availability and Resilience",
                "L1", ERROR, notes=f"HA pairs API failed: {e}")

        # Also check for FTD clustering (active/active)
        clusters = []
        try:
            cdata    = self.session._config_get("deviceclusters/ftddeviceclusters")
            clusters = cdata.get("items", [])
        except Exception:
            pass   # Endpoint may not exist on this version — not an error

        if pairs or clusters:
            desc = []
            for p in pairs:
                primary   = p.get("primary",   {}).get("name", "?")
                secondary = p.get("secondary", {}).get("name", "?")
                desc.append(f"HA pair: {primary} ↔ {secondary}")
            for c in clusters:
                desc.append(f"Cluster: {c.get('name','?')}")
            return make_result(
                "HA-1", "High Availability and Resilience",
                "L1", PASS,
                actual=f"{len(pairs)} HA pair(s), {len(clusters)} cluster(s): {'; '.join(desc)}",
                notes=f"FTD HA pairs: {len(pairs)}, clusters: {len(clusters)}")

        return make_result(
            "HA-1", "High Availability and Resilience",
            "L1", FAIL,
            expected="At least one FTD HA pair or cluster configured",
            actual="No HA pairs or clusters found",
            remediation=(
                "Devices > Device Management > Add HA. "
                "Configure FTD High Availability with an active/standby pair. "
                "For critical deployments, consider FTD clustering for active/active load sharing."
            ),
            notes="Checked /devicehapairs/ftddevicehapairs and /deviceclusters/ftddeviceclusters",
            risk_description=(
                "Single FTD device with no failover — any hardware or software failure causes "
                "a complete loss of firewall protection."
            ),
            default_risk_level="High",
        )
