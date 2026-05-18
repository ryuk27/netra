"""
Subdomain enumeration using Certificate Transparency logs
"""

import re
import time
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from .header_analyzer import HeaderAnalyzer
import threading
from .scan_cache import ScanCache
from .wordlist_bruteforce import WordlistBruteforcer

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

from .base_module import BaseModule
from .screenshot_capture import ScreenshotCapture
from .dashboard import DashboardGenerator
from .content_analyzer import ContentAnalyzer
from .correlator import Correlator
from .threat_intel_aggregator import ThreatIntelAggregator


class _TitleParser(HTMLParser):
    """Minimal HTML parser that extracts the <title> tag content."""

    def __init__(self):
        super().__init__()
        self._in_title = False
        self.title: Optional[str] = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self._in_title = True

    def handle_data(self, data):
        if self._in_title:
            self.title = data.strip()

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False


class SubdomainEnumerator(BaseModule):
    """Discovers subdomains using Certificate Transparency logs"""

    # Expanded alive codes to catch more response types (any HTTP response = server is alive)
    ALIVE_CODES = {200, 201, 204, 301, 302, 304, 307, 308, 400, 401, 402, 403, 404, 405, 406, 408, 409, 410, 429, 500, 502, 503, 504}
    ERROR_CODES = {500, 502, 503, 504}

    DEFAULT_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }

    def __init__(
        self,
        target: str,
        probe_timeout: int = 10,
        screenshot_dir: str = "screenshots",
        capture_screenshots: bool = True,
        report_path: str = "reports",
        max_workers: int = 20,
        rate_limit: float = 0.1,
        use_cache: bool = True,
        bruteforce: bool = True,
        wordlist_path: Optional[str] = None,
        virustotal_key: Optional[str] = None,
        abuseipdb_key: Optional[str] = None,
        otx_key: Optional[str] = None,
    ):
        super().__init__(target)
        self.crt_sh_url = "https://crt.sh"
        self.probe_timeout = probe_timeout
        self.capture_screenshots = capture_screenshots
        self.screenshot_dir = screenshot_dir
        self.report_path = report_path
        self.max_workers = max_workers
        self.rate_limit = rate_limit  # seconds between requests per thread
        self._rate_lock = threading.Lock()
        self._last_request_time = 0.0
        self.use_cache = use_cache
        self.cache = ScanCache(target) if use_cache else None
        self.bruteforce = bruteforce
        self.wordlist_path = wordlist_path
        
        # Initialize threat intelligence aggregator
        self.threat_intel = ThreatIntelAggregator(
            virustotal_key=virustotal_key,
            abuseipdb_key=abuseipdb_key,
            otx_key=otx_key,
            timeout=probe_timeout
        )
        self.threat_intel_enabled = self.threat_intel.is_enabled()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------
    def collect(self) -> Dict[str, Any]:
        """Collect subdomains from CT logs, probe each, and classify."""
        self.logger.info("Starting subdomain enumeration for {}".format(self.target))

        subdomain_names: List[str] = []

        # --- Check cache for subdomain list ---
        if self.cache and self.cache.has_cache():
            cached_subs = self.cache.get_subdomains()
            if cached_subs:
                self.logger.info("Loaded {} cached subdomains".format(len(cached_subs)))
                subdomain_names = cached_subs
                # Ensure main target is always included
                if self.target not in subdomain_names:
                    subdomain_names.insert(0, self.target)

        if not subdomain_names:
            try:
                subdomain_set: Set[str] = set()

                # Source 1: crt.sh
                crtsh_results = self._query_crtsh()
                for cert in crtsh_results:
                    name_value = cert.get("name_value", "")
                    subdomain_set.update(self._extract_domains(name_value))

                # Source 2: HackerTarget
                ht_results = self._query_hackertarget()
                subdomain_set.update(ht_results)

                # Source 3: Wordlist brute-force
                if self.bruteforce:
                    self.logger.info("Starting wordlist brute-force…")
                    bruter = WordlistBruteforcer(
                        target=self.target,
                        max_workers=self.max_workers,
                        wordlist_path=self.wordlist_path,
                    )
                    bf_results = bruter.run()
                    new_from_bf = bf_results - subdomain_set
                    if new_from_bf:
                        self.logger.info(
                            "Brute-force found {} new subdomains (not in passive sources)".format(
                                len(new_from_bf)
                            )
                        )
                    subdomain_set.update(bf_results)

                subdomain_names = self._filter_subdomains(subdomain_set)
                
                # Always include the main target domain
                if self.target not in subdomain_names:
                    subdomain_names.insert(0, self.target)

                # Save to cache
                if self.cache:
                    self.cache.save_subdomains(subdomain_names)

            except Exception as e:
                self.logger.error("Subdomain enumeration failed: {}".format(e))

        self.logger.info(
            "Found {} unique subdomains — probing…".format(len(subdomain_names))
        )

        # --- DNS pre-check ---
        self.logger.info("Running DNS pre-check on {} subdomains…".format(len(subdomain_names)))
        resolving = self._dns_precheck(subdomain_names)
        skipped_dns = len(subdomain_names) - len(resolving)
        if skipped_dns > 0:
            self.logger.info("Skipped {} non-resolving subdomains".format(skipped_dns))

        # Reset socket timeout after DNS check (DNS precheck sets it to 3 seconds)
        socket.setdefaulttimeout(None)

        # --- Check cache for already-probed results ---
        already_probed: Dict[str, Dict[str, Any]] = {}
        to_probe: List[str] = resolving
        if self.cache and self.cache.has_cache():
            already_probed = self.cache.get_probed()
            cached_names = set(already_probed.keys())
            to_probe = [n for n in resolving if n not in cached_names]
            if already_probed:
                self.logger.info(
                    "Resuming — {} already probed, {} remaining".format(
                        len(cached_names & set(resolving)), len(to_probe)
                    )
                )

        # --- Probe remaining subdomains (concurrent) ---
        self.logger.info(
            "Probing {} subdomains with {} threads…".format(len(to_probe), self.max_workers)
        )
        new_probed: List[Dict[str, Any]] = self._probe_all(to_probe)

        # Save new results to cache
        if self.cache:
            for entry in new_probed:
                self.cache.save_probed(entry["subdomain"], entry)

        # Merge cached + new results
        probed: List[Dict[str, Any]] = []
        probed_names: Set[str] = set()
        for entry in new_probed:
            probed.append(entry)
            probed_names.add(entry["subdomain"])
        for name, cached_entry in already_probed.items():
            if name not in probed_names and name in set(resolving):
                probed.append(cached_entry)
                probed_names.add(name)

        # Add non-resolving subdomains as dead
        for name in subdomain_names:
            if name not in probed_names:
                probed.append({
                    "subdomain": name,
                    "alive": False,
                    "status_code": None,
                    "title": None,
                    "redirect_url": None,
                    "content_length": None,
                    "response_time": None,
                    "dns_resolves": False,
                })

        # --- Classify ---
        classified = self._classify(probed)

        self.logger.info(
            "Probe complete — alive: {}, dead: {}, error: {}".format(
                len(classified['alive']), len(classified['dead']), len(classified['error'])
            )
        )

        # --- Screenshot capture ---
        if self.capture_screenshots:
            alive_count = len(classified["alive"])
            if alive_count > 50:
                self.logger.info(
                    f"Skipping screenshots for {alive_count} alive subdomains (too many). "
                    f"Use --no-screenshots or reduce target scope."
                )
                for entry in probed:
                    entry["screenshot_path"] = None
            else:
                self.logger.info("Capturing screenshots of alive subdomains…")
                output_path = str(
                    Path(self.screenshot_dir) / self.target.replace(".", "_")
                )
                capturer = ScreenshotCapture(output_dir=output_path)
                capturer.capture_all(probed)
                screenshots_taken = sum(
                    1 for p in probed if p.get("screenshot_path") is not None
                )
                self.logger.info(f"Screenshots captured: {screenshots_taken}")
        else:
            for entry in probed:
                entry["screenshot_path"] = None

        # --- Content analysis ---
        self.logger.info("Analyzing content of probed subdomains…")
        analyzer = ContentAnalyzer()
        analyzer.analyze_all(probed)

        high_interest = [
            e["subdomain"] for e in probed
            if e.get("content_analysis", {}).get("risk_level") in ("critical", "high")
        ]
        if high_interest:
            self.logger.warning(
                f"High-interest targets found: {', '.join(high_interest)}"
            )

        # --- Threat intelligence enrichment ---
        if self.threat_intel_enabled:
            self.logger.info("Enriching subdomains with threat intelligence data...")
            alive_subdomains = [e["subdomain"] for e in probed if e.get("alive")]
            if alive_subdomains:
                threat_data = self.threat_intel.check_subdomains(alive_subdomains[:50])  # Limit to 50
                for entry in probed:
                    if entry["subdomain"] in threat_data:
                        entry["threat_intelligence"] = threat_data[entry["subdomain"]]
                        # Save enriched entry back to cache
                        if self.cache:
                            self.cache.save_probed(entry["subdomain"], entry)
                self.logger.info(f"Threat intelligence data collected for {len(threat_data)} subdomains")
            else:
                self.logger.info("No alive subdomains to enrich with threat intelligence")
        else:
            self.logger.debug("Threat intelligence disabled (no API keys provided)")
            for entry in probed:
                entry["threat_intelligence"] = None

        # --- Build output dict ---
        output: Dict[str, Any] = {
            "target": self.target,
            "total_unique": len(subdomain_names),
            "subdomains": probed,
            "summary": {
                "alive": len(classified["alive"]),
                "dead": len(classified["dead"]),
                "error": len(classified["error"]),
            },
            "alive": classified["alive"],
            "dead": classified["dead"],
            "error": classified["error"],
            "high_interest": high_interest,
        }

        # --- Cross-module correlation ---
        self.logger.info("Running cross-module correlation…")
        try:
            correlator = Correlator()
            correlated_findings = correlator.correlate(output)
            output["correlated_findings"] = correlated_findings
            self.logger.info(
                f"Correlation complete — {len(correlated_findings)} finding(s) identified"
            )
        except Exception as e:
            self.logger.error(f"Correlation failed: {e}")
            output["correlated_findings"] = []

        # --- Generate HTML dashboard ---
        try:
            report_file = str(
                Path(self.report_path) / f"{self.target.replace('.', '_')}.html"
            )
            dashboard = DashboardGenerator(output_path=report_file)
            saved = dashboard.generate(output)
            output["report_path"] = saved
            self.logger.info(f"HTML dashboard saved to {saved}")
        except Exception as e:
            self.logger.error(f"Dashboard generation failed: {e}")
            output["report_path"] = None

        return output

    # ------------------------------------------------------------------
    # Subdomain sources
    # ------------------------------------------------------------------
    def _query_crtsh(self, retries: int = 3) -> List[Dict[str, Any]]:
        """Query crt.sh with retry logic and robust error handling."""
        url = f"{self.crt_sh_url}/?q=%.{self.target}&output=json"
        last_error = None

        for attempt in range(1, retries + 1):
            try:
                self.logger.info(f"Querying crt.sh (attempt {attempt}/{retries})…")
                resp = requests.get(
                    url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=90,
                )

                self.logger.debug(f"crt.sh status: {resp.status_code}, length: {len(resp.text)}")

                if resp.status_code != 200:
                    self.logger.warning(f"crt.sh returned HTTP {resp.status_code}")
                    last_error = f"HTTP {resp.status_code}"
                    time.sleep(5 * attempt)
                    continue

                text = resp.text.strip()
                if not text or text.startswith("<"):
                    self.logger.warning("crt.sh returned empty or HTML (rate-limited?)")
                    last_error = "Empty or HTML response"
                    time.sleep(10 * attempt)
                    continue

                data = resp.json()

                if not isinstance(data, list):
                    self.logger.warning(f"crt.sh returned unexpected type: {type(data)}")
                    last_error = "Unexpected JSON type"
                    time.sleep(5 * attempt)
                    continue

                self.logger.info(f"crt.sh returned {len(data)} certificate entries")
                return data

            except requests.exceptions.JSONDecodeError as e:
                self.logger.warning(f"crt.sh JSON parse error: {e}")
                last_error = str(e)
                time.sleep(5 * attempt)
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"crt.sh request error: {e}")
                last_error = str(e)
                time.sleep(5 * attempt)

        self.logger.error(f"crt.sh failed after {retries} attempts: {last_error}")
        return []

    def _query_hackertarget(self) -> Set[str]:
        """Backup source: HackerTarget free API (no key needed, 100/day limit)."""
        url = f"https://api.hackertarget.com/hostsearch/?q={self.target}"
        domains: Set[str] = set()

        try:
            self.logger.info("Querying HackerTarget API (backup source)…")
            resp = requests.get(url, headers=self.DEFAULT_HEADERS, timeout=30)

            if resp.status_code != 200:
                self.logger.warning(f"HackerTarget returned HTTP {resp.status_code}")
                return domains

            text = resp.text.strip()
            if "error" in text.lower() or "api count" in text.lower():
                self.logger.warning(f"HackerTarget API limit reached: {text[:100]}")
                return domains

            for line in text.split("\n"):
                line = line.strip()
                if "," in line:
                    hostname = line.split(",")[0].strip()
                    if self.validate_domain(hostname):
                        domains.add(hostname.lower())

            self.logger.info(f"HackerTarget returned {len(domains)} subdomains")

        except Exception as e:
            self.logger.warning(f"HackerTarget query failed: {e}")

        return domains

    # ------------------------------------------------------------------
    # DNS pre-check
    # ------------------------------------------------------------------
    def _dns_precheck(self, subdomain_names: List[str]) -> List[str]:
        """Resolve DNS for all subdomains concurrently. Return only those that resolve."""
        resolving: List[str] = []
        total = len(subdomain_names)

        if TQDM_AVAILABLE:
            pbar = tqdm(total=total, desc="🔍 DNS check", unit="host", ncols=80)
        else:
            pbar = None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_name = {
                executor.submit(self._resolve_dns, name): name
                for name in subdomain_names
            }

            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    if future.result():
                        resolving.append(name)
                except Exception:
                    pass
                if pbar:
                    pbar.update(1)

        if pbar:
            pbar.close()

        return sorted(resolving)

    @staticmethod
    def _resolve_dns(subdomain: str) -> bool:
        """Check if a subdomain resolves in DNS."""
        try:
            socket.setdefaulttimeout(3)
            socket.getaddrinfo(subdomain, None)
            return True
        except (socket.gaierror, socket.timeout, OSError):
            return False

    # ------------------------------------------------------------------
    # Concurrent probing
    # ------------------------------------------------------------------
    def _probe_all(self, subdomain_names: List[str]) -> List[Dict[str, Any]]:
        """Probe all subdomains concurrently using a thread pool."""
        if not subdomain_names:
            return []

        results: Dict[str, Dict[str, Any]] = {}
        total = len(subdomain_names)

        if TQDM_AVAILABLE:
            pbar = tqdm(total=total, desc="🌐 Probing", unit="host", ncols=80)
        else:
            pbar = None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_name = {
                executor.submit(self._probe_subdomain, name): name
                for name in subdomain_names
            }

            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    result = future.result()
                    results[name] = result
                except Exception as e:
                    self.logger.error("Probe error for {}: {}".format(name, e))
                    results[name] = {
                        "subdomain": name, "alive": False,
                        "status_code": None, "title": None,
                        "redirect_url": None, "content_length": None,
                        "response_time": None,
                    }
                if pbar:
                    pbar.update(1)

        if pbar:
            pbar.close()

        return [results[name] for name in sorted(results.keys())]

    # ------------------------------------------------------------------
    # HTTP probing
    # ------------------------------------------------------------------
    def _probe_subdomain(self, subdomain: str) -> Dict[str, Any]:
        """Send an HTTP(S) request to *subdomain* and record metadata."""
        result: Dict[str, Any] = {
            "subdomain": subdomain,
            "alive": False,
            "status_code": None,
            "title": None,
            "redirect_url": None,
            "content_length": None,
            "response_time": None,
            "headers": {},
            "header_analysis": None,
        }

        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                start = time.monotonic()
                resp = self._make_request(url, allow_redirects=False)

                redirect_url = None
                if resp.is_redirect or resp.is_permanent_redirect:
                    redirect_url = resp.headers.get("Location")
                    try:
                        resp = self._make_request(url, allow_redirects=True)
                    except Exception:
                        pass

                elapsed = round(time.monotonic() - start, 3)

                result["alive"] = True
                result["status_code"] = resp.status_code
                result["response_time"] = elapsed
                result["content_length"] = len(resp.content)
                result["redirect_url"] = redirect_url
                result["headers"] = dict(resp.headers)

                # Analyze security headers
                analyzer = HeaderAnalyzer()
                result["header_analysis"] = analyzer.analyze_headers(dict(resp.headers))

                content_type = resp.headers.get("Content-Type", "")
                if "html" in content_type.lower():
                    result["title"] = self._extract_title(resp.text)

                break

            except Exception as e:
                self.logger.debug("Probe failed {}: {}".format(url, e))
                continue

        if not result["alive"]:
            self.logger.debug("Subdomain unreachable: {}".format(subdomain))

        return result

    def _make_request(self, url: str, allow_redirects: bool = False):
        """Make an HTTP request with rate limiting, headers, timeout, and SSL handling."""
        # Rate limiting removed - _throttle() method not implemented

        kwargs = {
            "headers": self.DEFAULT_HEADERS,
            "timeout": self.probe_timeout,
            "allow_redirects": allow_redirects,
            "verify": True,
        }

        try:
            return requests.get(url, **kwargs)
        except requests.exceptions.SSLError:
            self.logger.debug("SSL error for {}, retrying without verification".format(url))
            kwargs["verify"] = False
            return requests.get(url, **kwargs)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_title(html: str) -> Optional[str]:
        """Return the <title> text from an HTML document, or None."""
        try:
            parser = _TitleParser()
            parser.feed(html[:4096])
            return parser.title
        except Exception:
            return None

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Check if a string looks like a valid domain name."""
        pattern = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
        return bool(re.match(pattern, domain))

    def _extract_domains(self, text: str) -> Set[str]:
        """Extract valid domain names from a certificate name_value field."""
        domains: Set[str] = set()
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("*") or not line:
                continue
            if self.validate_domain(line):
                domains.add(line.lower())
        return domains

    def _filter_subdomains(self, subdomains: Set[str]) -> List[str]:
        """Filter subdomains to only include target domain."""
        filtered = [
            s for s in subdomains
            if s.endswith(f".{self.target}") or s == self.target
        ]
        return sorted(set(filtered))

    def _classify(
        self, probed: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """Bucket probed subdomains into alive / dead / error."""
        alive: List[str] = []
        dead: List[str] = []
        error: List[str] = []

        for entry in probed:
            name = entry["subdomain"]
            code = entry.get("status_code")

            if not entry["alive"] or code is None:
                dead.append(name)
            elif code in self.ERROR_CODES:
                error.append(name)
            elif code in self.ALIVE_CODES:
                alive.append(name)
            else:
                alive.append(name)

        return {"alive": sorted(alive), "dead": sorted(dead), "error": sorted(error)}
