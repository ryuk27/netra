"""
Subdomain wordlist brute-forcer — discovers subdomains by resolving
common names via DNS lookups.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Set
import logging

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# Built-in wordlist — top 150 most common subdomain prefixes
DEFAULT_WORDLIST = [
    "admin", "api", "app", "apps", "auth", "autodiscover", "autoconfig",
    "backup", "beta", "billing", "blog", "board", "build",
    "cdn", "chat", "ci", "client", "cloud", "cms", "console", "corp",
    "cpanel", "crm", "cs", "dashboard", "data", "db", "demo", "deploy",
    "dev", "dev2", "developer", "dns", "docs", "download",
    "elastic", "email", "exchange", "external",
    "files", "firewall", "forum", "ftp",
    "gateway", "git", "gitlab", "go", "grafana", "graphql",
    "help", "helpdesk", "home", "host", "hr", "hub",
    "id", "imap", "info", "internal", "intranet", "iot", "ir", "it",
    "jenkins", "jira", "jobs",
    "kb", "kibana",
    "lab", "labs", "ldap", "legacy", "link", "links", "linux", "live",
    "login", "log", "logs",
    "m", "mail", "mail2", "manage", "manager", "media", "meet",
    "mobile", "monitor", "monitoring", "mqtt", "mx", "my",
    "nas", "net", "new", "news", "ns", "ns1", "ns2", "ntp",
    "office", "old", "ops", "oracle", "origin", "outlook",
    "panel", "partner", "pay", "payments", "php", "pilot", "pop",
    "portal", "postgres", "preview", "private", "prod", "prometheus", "proxy",
    "qa", "queue",
    "rdp", "redis", "relay", "remote", "repo", "report", "reports",
    "sandbox", "search", "secure", "security", "server", "service",
    "services", "sftp", "shop", "signin", "signup", "site", "sites",
    "smtp", "soc", "splash", "sql", "sso", "stage", "staging",
    "static", "stats", "status", "storage", "store", "support", "svn",
    "test", "test2", "testing", "time", "tools", "track", "tracker",
    "uat", "upload",
    "vault", "video", "vm", "vpn", "vps",
    "web", "webmail", "wiki", "wip", "work", "wp", "www", "www2",
    "xml",
    "zabbix", "zendesk",
]


class WordlistBruteforcer:
    """Discovers subdomains by brute-forcing common names via DNS."""

    def __init__(
        self,
        target: str,
        max_workers: int = 30,
        timeout: float = 3.0,
        wordlist_path: Optional[str] = None,
    ):
        self.target = target
        self.max_workers = max_workers
        self.timeout = timeout
        self.logger = logging.getLogger("WordlistBruteforcer")
        self.wordlist = self._load_wordlist(wordlist_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def run(self) -> Set[str]:
        """
        Brute-force subdomains and return a set of those that resolve.
        """
        candidates = ["{}.{}".format(word, self.target) for word in self.wordlist]
        found: Set[str] = set()
        total = len(candidates)

        if TQDM_AVAILABLE:
            pbar = tqdm(total=total, desc="🔨 Brute-force", unit="name", ncols=80)
        else:
            pbar = None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_name = {
                executor.submit(self._resolve, name): name
                for name in candidates
            }

            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    if future.result():
                        found.add(name.lower())
                except Exception:
                    pass
                if pbar:
                    pbar.update(1)

        if pbar:
            pbar.close()

        return found

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _resolve(self, hostname: str) -> bool:
        """Check if hostname resolves in DNS."""
        try:
            socket.setdefaulttimeout(self.timeout)
            socket.getaddrinfo(hostname, None)
            return True
        except (socket.gaierror, socket.timeout, OSError):
            return False

    def _load_wordlist(self, path: Optional[str]) -> List[str]:
        """Load wordlist from file or use built-in default."""
        if path:
            p = Path(path)
            if p.exists():
                words = []
                for line in p.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        words.append(line.lower())
                self.logger.info("Loaded custom wordlist: {} ({} words)".format(p.name, len(words)))
                return words
            else:
                self.logger.warning("Wordlist not found: {} — falling back to default".format(path))

        self.logger.info("Using built-in wordlist ({} words)".format(len(DEFAULT_WORDLIST)))
        return list(DEFAULT_WORDLIST)
