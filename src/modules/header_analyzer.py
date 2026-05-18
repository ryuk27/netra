"""
HTTP security headers analyzer — checks for missing or misconfigured
security headers on alive subdomains.
"""

from typing import Any, Dict, List, Optional


# Header name → (description, severity if missing, recommendation)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "HSTS — forces HTTPS connections",
        "medium",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header.",
    ),
    "Content-Security-Policy": (
        "CSP — prevents XSS and injection attacks",
        "medium",
        "Implement a Content-Security-Policy header to restrict resource loading.",
    ),
    "X-Frame-Options": (
        "Clickjacking protection",
        "medium",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
    ),
    "X-Content-Type-Options": (
        "MIME-sniffing protection",
        "low",
        "Add 'X-Content-Type-Options: nosniff' header.",
    ),
    "X-XSS-Protection": (
        "Legacy XSS filter",
        "low",
        "Add 'X-XSS-Protection: 1; mode=block' header (or rely on CSP).",
    ),
    "Referrer-Policy": (
        "Controls referrer information leakage",
        "low",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' header.",
    ),
    "Permissions-Policy": (
        "Controls browser feature access (camera, mic, etc.)",
        "low",
        "Add a Permissions-Policy header to restrict browser features.",
    ),
}

# Dangerous headers that should NOT be present
LEAKY_HEADERS = {
    "Server": "Reveals server software and version — aids attacker fingerprinting.",
    "X-Powered-By": "Reveals backend technology — aids attacker fingerprinting.",
    "X-AspNet-Version": "Reveals ASP.NET version — aids attacker fingerprinting.",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version — aids attacker fingerprinting.",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class HeaderAnalyzer:
    """Analyzes HTTP response headers for security issues."""

    def analyze_headers(
        self, headers: Optional[Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        Analyze a dict of HTTP response headers.

        Returns::

            {
                "missing": [{"header": str, "severity": str, "description": str, "remediation": str}],
                "leaky": [{"header": str, "value": str, "note": str}],
                "present": [str],
                "score": 0-100,
                "grade": "A".."F",
            }
        """
        if not headers:
            return {
                "missing": [],
                "leaky": [],
                "present": [],
                "score": 0,
                "grade": "?",
            }

        # Normalise header keys for case-insensitive lookup
        norm: Dict[str, str] = {k.lower(): v for k, v in headers.items()}
        raw_keys: Dict[str, str] = {k.lower(): k for k in headers}

        missing: List[Dict[str, str]] = []
        present: List[str] = []

        for header, (desc, severity, remediation) in SECURITY_HEADERS.items():
            if header.lower() in norm:
                present.append(header)
            else:
                missing.append({
                    "header": header,
                    "severity": severity,
                    "description": desc,
                    "remediation": remediation,
                })

        leaky: List[Dict[str, str]] = []
        for header, note in LEAKY_HEADERS.items():
            if header.lower() in norm:
                leaky.append({
                    "header": header,
                    "value": norm[header.lower()],
                    "note": note,
                })

        # Score: start at 100, deduct per missing/leaky header
        deductions = {"medium": 15, "low": 8}
        score = 100
        for m in missing:
            score -= deductions.get(m["severity"], 5)
        for _ in leaky:
            score -= 5
        score = max(0, score)

        grade = self._grade(score)

        return {
            "missing": missing,
            "leaky": leaky,
            "present": present,
            "score": score,
            "grade": grade,
        }

    @staticmethod
    def _grade(score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 55:
            return "C"
        if score >= 35:
            return "D"
        return "F"
