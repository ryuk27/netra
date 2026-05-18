"""
Scan cache — saves and loads probing progress to allow resuming interrupted scans.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class ScanCache:
    """Persists scan progress to a JSON file for resume support."""

    def __init__(self, target: str, cache_dir: str = ".netra_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        safe_name = target.replace(".", "_").replace(":", "_")
        self.cache_file = self.cache_dir / f"{safe_name}.cache.json"
        self._data: Dict[str, Any] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def has_cache(self) -> bool:
        """Return True if a usable cache exists for this target."""
        if not self._data:
            return False
        # Cache expires after 24 hours
        created = self._data.get("created", 0)
        return (time.time() - created) < 86400

    def get_probed(self) -> Dict[str, Dict[str, Any]]:
        """Return dict of already-probed subdomains {name: result}."""
        return self._data.get("probed", {})

    def get_probed_names(self) -> Set[str]:
        """Return set of subdomain names that have already been probed."""
        return set(self._data.get("probed", {}).keys())

    def get_subdomains(self) -> Optional[List[str]]:
        """Return cached subdomain list, or None if not cached."""
        return self._data.get("subdomains")

    def save_subdomains(self, subdomains: List[str]) -> None:
        """Cache the enumerated subdomain list."""
        self._data["subdomains"] = subdomains
        self._data.setdefault("created", time.time())
        self._flush()

    def save_probed(self, name: str, result: Dict[str, Any]) -> None:
        """Cache a single probed result."""
        probed = self._data.setdefault("probed", {})
        # Strip non-serializable fields
        clean = {}
        for k, v in result.items():
            if k == "headers":
                continue  # too large, skip
            clean[k] = v
        probed[name] = clean
        self._flush()

    def clear(self) -> None:
        """Delete the cache file."""
        if self.cache_file.exists():
            self.cache_file.unlink()
        self._data = {}

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _load(self) -> None:
        if self.cache_file.exists():
            try:
                self._data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}
        else:
            self._data = {}

    def _flush(self) -> None:
        try:
            self.cache_file.write_text(
                json.dumps(self._data, default=str, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass
