"""
Cross-module correlator — finds relationships between findings from
different recon modules and flags compound risks.
"""

from typing import Any, Dict, List, Optional, Set


class Finding:
    """A single correlated finding with severity and evidence."""

    __slots__ = ("severity", "title", "description", "evidence", "remediation")

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def __init__(
        self,
        severity: str,
        title: str,
        description: str,
        evidence: Optional[List[str]] = None,
        remediation: Optional[str] = None,
    ):
        self.severity = severity
        self.title = title
        self.description = description
        self.evidence = evidence or []
        self.remediation = remediation or ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    def __lt__(self, other: "Finding") -> bool:
        return self.SEVERITY_ORDER.get(self.severity, 5) < self.SEVERITY_ORDER.get(
            other.severity, 5
        )


class Correlator:
    """
    Accepts the full recon data dict and produces correlated findings.

    Expected keys in *data*:
        - subdomains   (list of probed dicts from SubdomainEnumerator)
        - technology_fingerprint (dict, optional — from TechFingerprinter)
        - email_harvest (dict, optional — from EmailHarvester)
        - git_exposure  (dict, optional — from GitExposureScanner)
        - shodan        (dict, optional — from ShodanScanner)
    """

    def correlate(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings: List[Finding] = []

        subdomains = data.get("subdomains", [])
        tech = data.get("technology_fingerprint", {})
        emails = data.get("email_harvest", {})
        git = data.get("git_exposure", {})
        shodan = data.get("shodan", {})

        findings.extend(self._correlate_exposed_admin(subdomains, tech))
        findings.extend(self._correlate_dev_staging(subdomains))
        findings.extend(self._correlate_default_installs(subdomains, tech))
        findings.extend(self._correlate_git_secrets(subdomains, git))
        findings.extend(self._correlate_email_admin(subdomains, emails))
        findings.extend(self._correlate_open_databases(subdomains, shodan))
        findings.extend(self._correlate_cicd(subdomains))
        findings.extend(self._correlate_login_without_https(subdomains))
        findings.extend(self._correlate_high_attack_surface(subdomains))
        findings.extend(self._correlate_weak_headers(subdomains))

        findings.sort()
        return [f.to_dict() for f in findings]

    # ------------------------------------------------------------------
    # Correlation rules
    # ------------------------------------------------------------------

    @staticmethod
    def _correlate_exposed_admin(
        subdomains: List[Dict[str, Any]], tech: Dict[str, Any]
    ) -> List[Finding]:
        findings: List[Finding] = []
        for entry in subdomains:
            tags: List[str] = entry.get("tags", [])
            name = entry.get("subdomain", "")
            if "admin-panel" not in tags:
                continue

            severity = "high"
            evidence = [f"Admin panel detected at {name}"]

            # Escalate if old tech is running on same host
            host_tech = tech.get(f"https://{name}", tech.get(f"http://{name}", {}))
            server = host_tech.get("server", "")
            if server:
                evidence.append(f"Server: {server}")
                # Simple version-age heuristic
                if any(old in server.lower() for old in ("apache/2.2", "apache/2.0", "nginx/1.1", "iis/7", "iis/6")):
                    severity = "critical"
                    evidence.append("Outdated server software detected on admin endpoint")

            findings.append(
                Finding(
                    severity=severity,
                    title=f"Admin panel exposed: {name}",
                    description=(
                        "An administrative interface is publicly accessible. "
                        "Combined with outdated software this is a critical risk."
                        if severity == "critical"
                        else "An administrative interface is publicly accessible."
                    ),
                    evidence=evidence,
                    remediation=(
                        "Restrict access via IP allowlist or VPN. "
                        "Enable MFA. Update server software to the latest version."
                    ),
                )
            )
        return findings

    @staticmethod
    def _correlate_dev_staging(subdomains: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        devs = [e for e in subdomains if "dev-staging" in e.get("tags", []) and e.get("alive")]
        if not devs:
            return findings
        names = [e["subdomain"] for e in devs]
        findings.append(
            Finding(
                severity="high",
                title=f"{len(devs)} development/staging environment(s) exposed",
                description=(
                    "Non-production environments are publicly reachable. "
                    "These often have weaker security controls and may contain test credentials."
                ),
                evidence=[f"Alive dev/staging host: {n}" for n in names],
                remediation="Move behind VPN or restrict to internal network. Remove test data and credentials.",
            )
        )
        return findings

    @staticmethod
    def _correlate_default_installs(
        subdomains: List[Dict[str, Any]], tech: Dict[str, Any]
    ) -> List[Finding]:
        findings: List[Finding] = []
        defaults = [e for e in subdomains if "default-install" in e.get("tags", [])]
        if not defaults:
            return findings
        names = [e["subdomain"] for e in defaults]
        findings.append(
            Finding(
                severity="high",
                title=f"{len(defaults)} unconfigured default server page(s) found",
                description=(
                    "Default web server pages indicate servers that were deployed "
                    "but never properly configured — a common entry point for attackers."
                ),
                evidence=[f"Default page: {n}" for n in names],
                remediation="Remove default pages, configure virtual hosts, or decommission unused servers.",
            )
        )
        return findings

    @staticmethod
    def _correlate_git_secrets(
        subdomains: List[Dict[str, Any]], git: Dict[str, Any]
    ) -> List[Finding]:
        findings: List[Finding] = []
        exposed_repos = git.get("exposed_repos", [])
        secrets = git.get("secrets", [])
        if not exposed_repos and not secrets:
            return findings

        evidence: List[str] = []
        severity = "high"
        if exposed_repos:
            evidence.append(f"{len(exposed_repos)} exposed .git repo(s)")
        if secrets:
            severity = "critical"
            evidence.append(f"{len(secrets)} secret(s)/credential(s) found in code")

        findings.append(
            Finding(
                severity=severity,
                title="Git repository / secrets exposure",
                description=(
                    "Source code or credentials have been found publicly accessible. "
                    "Attackers can extract API keys, passwords, and internal architecture details."
                ),
                evidence=evidence,
                remediation=(
                    "Immediately rotate all exposed credentials. "
                    "Block public access to .git directories. "
                    "Add .gitignore rules and use secret management tools."
                ),
            )
        )
        return findings

    @staticmethod
    def _correlate_email_admin(
        subdomains: List[Dict[str, Any]], emails: Dict[str, Any]
    ) -> List[Finding]:
        findings: List[Finding] = []
        addresses: List[str] = emails.get("emails", [])
        admin_emails = [e for e in addresses if any(
            kw in e.lower() for kw in ("admin", "root", "postmaster", "webmaster")
        )]
        if not admin_emails:
            return findings
        findings.append(
            Finding(
                severity="medium",
                title=f"{len(admin_emails)} administrative email address(es) publicly visible",
                description=(
                    "Admin-role email addresses are discoverable and can be used "
                    "for targeted phishing or password-reset attacks."
                ),
                evidence=[f"Email: {e}" for e in admin_emails],
                remediation="Use role aliases behind a ticket system. Enable MFA on all admin accounts.",
            )
        )
        return findings

    @staticmethod
    def _correlate_open_databases(
        subdomains: List[Dict[str, Any]], shodan: Dict[str, Any]
    ) -> List[Finding]:
        findings: List[Finding] = []
        db_subs = [e for e in subdomains if "database" in e.get("tags", []) and e.get("alive")]
        open_ports = shodan.get("open_ports", [])
        db_ports = {3306, 5432, 27017, 6379, 9200, 9300}
        exposed_db_ports = [p for p in open_ports if p in db_ports]

        if not db_subs and not exposed_db_ports:
            return findings

        evidence: List[str] = []
        if db_subs:
            evidence.extend(f"Database subdomain alive: {e['subdomain']}" for e in db_subs)
        if exposed_db_ports:
            evidence.extend(f"Database port open: {p}" for p in exposed_db_ports)

        findings.append(
            Finding(
                severity="critical",
                title="Database service(s) potentially exposed to the internet",
                description=(
                    "Database interfaces or ports are reachable from the public internet. "
                    "This can lead to data theft or complete system compromise."
                ),
                evidence=evidence,
                remediation="Firewall database ports to internal networks only. Use SSH tunnels or VPN for remote access.",
            )
        )
        return findings

    @staticmethod
    def _correlate_cicd(subdomains: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        cicd = [e for e in subdomains if "ci-cd" in e.get("tags", []) and e.get("alive")]
        if not cicd:
            return findings
        findings.append(
            Finding(
                severity="critical",
                title=f"CI/CD system(s) publicly accessible",
                description=(
                    "Continuous integration / deployment dashboards are reachable. "
                    "Compromise grants attackers the ability to inject code into production."
                ),
                evidence=[f"CI/CD host: {e['subdomain']}" for e in cicd],
                remediation="Place behind VPN. Enforce SSO with MFA. Audit pipeline permissions.",
            )
        )
        return findings

    @staticmethod
    def _correlate_login_without_https(subdomains: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        for entry in subdomains:
            if "login" not in entry.get("tags", []):
                continue
            # If we probed and it only responded on HTTP (status_code set but no HTTPS)
            # We approximate: if alive and subdomain doesn't appear in an HTTPS success, flag it
            # For simplicity, check if content was served (this is best-effort)
        return findings

    @staticmethod
    def _correlate_high_attack_surface(subdomains: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        alive = [e for e in subdomains if e.get("alive")]
        if len(alive) > 50:
            findings.append(
                Finding(
                    severity="medium",
                    title=f"Large attack surface — {len(alive)} alive subdomains",
                    description=(
                        "A high number of publicly reachable subdomains increases "
                        "the probability that at least one has a vulnerability."
                    ),
                    evidence=[f"Total alive subdomains: {len(alive)}"],
                    remediation="Audit and decommission unused subdomains. Consolidate services where possible.",
                )
            )
        return findings

    @staticmethod
    def _correlate_weak_headers(subdomains: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        weak: List[str] = []

        for entry in subdomains:
            ha = entry.get("header_analysis")
            if not ha or not entry.get("alive"):
                continue
            if ha.get("grade", "A") in ("D", "F"):
                weak.append(entry["subdomain"])

        if not weak:
            return findings

        findings.append(
            Finding(
                severity="medium",
                title="{} subdomain(s) with weak security headers".format(len(weak)),
                description=(
                    "Multiple alive subdomains are missing critical HTTP security headers "
                    "such as HSTS, CSP, and X-Frame-Options. This increases exposure to "
                    "XSS, clickjacking, and man-in-the-middle attacks."
                ),
                evidence=["Weak headers (grade D/F): {}".format(n) for n in weak[:10]],
                remediation=(
                    "Add Strict-Transport-Security, Content-Security-Policy, "
                    "X-Frame-Options, and X-Content-Type-Options headers to all web servers."
                ),
            )
        )
        return findings
