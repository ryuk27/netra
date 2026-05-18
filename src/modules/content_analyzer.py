"""
Content analysis — classifies alive subdomains by inspecting page metadata
and (optionally) screenshot image data.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


# ------------------------------------------------------------------
# Pattern banks
# ------------------------------------------------------------------
_TITLE_PATTERNS: Dict[str, List[re.Pattern]] = {
    "login": [
        re.compile(r"\b(log\s*in|sign\s*in|auth|sso|account)\b", re.I),
    ],
    "admin-panel": [
        re.compile(r"\b(admin|dashboard|control\s*panel|cpanel|webmin|phpmyadmin)\b", re.I),
    ],
    "api-docs": [
        re.compile(r"\b(swagger|redoc|api\s*doc|graphql|graphiql|playground)\b", re.I),
    ],
    "default-install": [
        re.compile(r"\b(welcome to nginx|apache.* default|it works!|iis windows|test page)\b", re.I),
        re.compile(r"\b(congratulations|default page|ubuntu|centos|debian)\b", re.I),
    ],
    "error-page": [
        re.compile(r"\b(404|not found|403 forbidden|500 internal|502 bad gateway|503 service)\b", re.I),
    ],
    "webmail": [
        re.compile(r"\b(roundcube|horde|zimbra|outlook|webmail|squirrelmail)\b", re.I),
    ],
    "dev-staging": [
        re.compile(r"\b(staging|development|debug|test environment)\b", re.I),
    ],
    "cms": [
        re.compile(r"\b(wordpress|joomla|drupal|magento|shopify|wix)\b", re.I),
    ],
}

_SUBDOMAIN_HINTS: Dict[str, List[re.Pattern]] = {
    "login": [re.compile(r"^(login|sso|auth|cas|accounts?)\.", re.I)],
    "admin-panel": [re.compile(r"^(admin|panel|manage|backend|console)\.", re.I)],
    "api-docs": [re.compile(r"^(api|docs|developer|graphql)\.", re.I)],
    "webmail": [re.compile(r"^(mail|webmail|smtp|imap|mx)\.", re.I)],
    "dev-staging": [re.compile(r"^(dev|stag|test|sandbox|uat|qa|beta|demo)\.", re.I)],
    "cdn-static": [re.compile(r"^(cdn|static|assets|media|img)\.", re.I)],
    "monitoring": [re.compile(r"^(grafana|kibana|prometheus|monitor|status|health)\.", re.I)],
    "ci-cd": [re.compile(r"^(jenkins|ci|cd|deploy|build|gitlab|drone)\.", re.I)],
    "database": [re.compile(r"^(db|database|mysql|postgres|mongo|redis|elastic)\.", re.I)],
    "vpn-internal": [re.compile(r"^(vpn|internal|intranet|corp)\.", re.I)],
}

_RISK_WEIGHTS: Dict[str, str] = {
    "login": "medium",
    "admin-panel": "high",
    "api-docs": "medium",
    "default-install": "high",
    "error-page": "low",
    "webmail": "medium",
    "dev-staging": "high",
    "cms": "low",
    "cdn-static": "info",
    "monitoring": "high",
    "ci-cd": "critical",
    "database": "critical",
    "vpn-internal": "high",
    "parking-page": "info",
    "blank-page": "low",
}


class ContentAnalyzer:
    """Classifies probed subdomains by content type and risk."""

    def analyze_all(self, probed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add ``tags`` and ``content_analysis`` to each entry in-place."""
        for entry in probed:
            tags, analysis = self._analyze_one(entry)
            entry["tags"] = sorted(tags)
            entry["content_analysis"] = analysis
        return probed

    # ------------------------------------------------------------------
    # Per-entry analysis
    # ------------------------------------------------------------------
    def _analyze_one(self, entry: Dict[str, Any]) -> tuple:
        tags: Set[str] = set()
        analysis: Dict[str, Any] = {"risk_level": "info", "notes": []}

        if not entry.get("alive"):
            analysis["notes"].append("Host did not respond")
            return tags, analysis

        subdomain: str = entry.get("subdomain", "")
        title: str = entry.get("title") or ""
        code: Optional[int] = entry.get("status_code")
        content_len: Optional[int] = entry.get("content_length")
        screenshot_path: Optional[str] = entry.get("screenshot_path")

        # --- Title-based classification ---
        for tag, patterns in _TITLE_PATTERNS.items():
            if any(p.search(title) for p in patterns):
                tags.add(tag)

        # --- Subdomain name hints ---
        for tag, patterns in _SUBDOMAIN_HINTS.items():
            if any(p.search(subdomain) for p in patterns):
                tags.add(tag)

        # --- Status-code heuristics ---
        if code == 401 or code == 407:
            tags.add("login")
            analysis["notes"].append("Authentication required (401/407)")
        if code == 403:
            tags.add("forbidden")
            analysis["notes"].append("Access forbidden — may still be interesting")

        # --- Content-length heuristics ---
        if content_len is not None and content_len < 200 and code == 200:
            tags.add("blank-page")
            analysis["notes"].append("Very small response body — possible parking / placeholder")

        # --- Screenshot image analysis (colour-based heuristics) ---
        if screenshot_path:
            img_tags = self._analyze_screenshot(screenshot_path)
            tags.update(img_tags)

        # --- Determine highest risk ---
        analysis["risk_level"] = self._highest_risk(tags)

        # --- Build human-readable notes ---
        if "admin-panel" in tags:
            analysis["notes"].append("Admin/management interface detected")
        if "default-install" in tags:
            analysis["notes"].append("Default server install page — likely unconfigured")
        if "dev-staging" in tags:
            analysis["notes"].append("Development/staging environment exposed")
        if "ci-cd" in tags:
            analysis["notes"].append("CI/CD system detected — high-value target")
        if "database" in tags:
            analysis["notes"].append("Database interface possibly exposed")
        if "api-docs" in tags:
            analysis["notes"].append("API documentation publicly accessible")

        return tags, analysis

    # ------------------------------------------------------------------
    # Screenshot pixel analysis
    # ------------------------------------------------------------------
    @staticmethod
    def _analyze_screenshot(path: str) -> Set[str]:
        """Simple pixel-stats heuristics on the screenshot."""
        tags: Set[str] = set()
        if not PIL_AVAILABLE:
            return tags

        try:
            img = Image.open(path).convert("RGB")
            pixels = list(img.getdata())
            total = len(pixels)

            # Dominant-colour check (parking / blank / error pages)
            white = sum(1 for r, g, b in pixels if r > 240 and g > 240 and b > 240)
            dark = sum(1 for r, g, b in pixels if r < 30 and g < 30 and b < 30)
            red = sum(1 for r, g, b in pixels if r > 180 and g < 80 and b < 80)

            if white / total > 0.92:
                tags.add("blank-page")
            if dark / total > 0.85:
                tags.add("blank-page")
            if red / total > 0.15:
                tags.add("error-page")

            # Unique colour count — very few colours → simple/default page
            sample = pixels[::max(1, total // 2000)]  # sample ≤ 2000 pixels
            unique = len(set(sample))
            if unique < 30:
                tags.add("parking-page")

        except Exception:
            pass

        return tags

    # ------------------------------------------------------------------
    # Risk calculation
    # ------------------------------------------------------------------
    @staticmethod
    def _highest_risk(tags: Set[str]) -> str:
        order = ["critical", "high", "medium", "low", "info"]
        best = "info"
        for tag in tags:
            level = _RISK_WEIGHTS.get(tag, "info")
            if order.index(level) < order.index(best):
                best = level
        return best
