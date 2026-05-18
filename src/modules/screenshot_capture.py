"""
Screenshot capture for alive subdomains.
Tries Playwright first, falls back to Selenium + Chrome.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

# --- Try Playwright ---
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# --- Try Selenium ---
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.common.exceptions import WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False


class ScreenshotCapture:
    """Captures browser screenshots of live HTTP endpoints."""

    def __init__(
        self,
        output_dir: str = "screenshots",
        timeout_ms: int = 15_000,
        viewport_width: int = 1440,
        viewport_height: int = 900,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_ms = timeout_ms
        self.viewport = {"width": viewport_width, "height": viewport_height}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def capture_all(self, probed: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Take a screenshot of every *alive* entry in *probed*.
        Adds ``screenshot_path`` key to each dict.
        """
        alive_entries = [e for e in probed if e.get("alive")]

        if not alive_entries:
            for entry in probed:
                entry["screenshot_path"] = None
            return probed

        if PLAYWRIGHT_AVAILABLE:
            self._capture_with_playwright(probed)
        elif SELENIUM_AVAILABLE:
            self._capture_with_selenium(probed)
        else:
            # No browser engine available — mark all as None
            for entry in probed:
                entry["screenshot_path"] = None

        return probed

    # ------------------------------------------------------------------
    # Playwright backend
    # ------------------------------------------------------------------
    def _capture_with_playwright(self, probed: List[Dict[str, Any]]) -> None:
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport=self.viewport,
                    ignore_https_errors=True,
                )

                for entry in probed:
                    if entry.get("alive"):
                        entry["screenshot_path"] = self._pw_capture_one(
                            context, entry["subdomain"]
                        )
                    else:
                        entry["screenshot_path"] = None

                context.close()
                browser.close()
        except Exception:
            # Playwright installed but browser binaries missing — fall back
            if SELENIUM_AVAILABLE:
                self._capture_with_selenium(probed)
            else:
                for entry in probed:
                    entry.setdefault("screenshot_path", None)

    def _pw_capture_one(self, context: Any, subdomain: str) -> Optional[str]:
        safe_name = subdomain.replace(".", "_").replace(":", "_")
        filepath = self.output_dir / f"{safe_name}.png"

        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            page = context.new_page()
            try:
                page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
                page.wait_for_timeout(1_500)
                page.screenshot(path=str(filepath), full_page=False)
                return str(filepath)
            except Exception:
                continue
            finally:
                page.close()

        return None

    # ------------------------------------------------------------------
    # Selenium backend (fallback)
    # ------------------------------------------------------------------
    def _capture_with_selenium(self, probed: List[Dict[str, Any]]) -> None:
        driver = None
        try:
            options = ChromeOptions()
            options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument(f"--window-size={self.viewport['width']},{self.viewport['height']}")
            options.add_argument("--ignore-certificate-errors")
            options.add_argument(
                "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )

            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(self.timeout_ms // 1000)

            for entry in probed:
                if entry.get("alive"):
                    entry["screenshot_path"] = self._selenium_capture_one(
                        driver, entry["subdomain"]
                    )
                else:
                    entry["screenshot_path"] = None

        except Exception:
            for entry in probed:
                entry.setdefault("screenshot_path", None)
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

    def _selenium_capture_one(self, driver: Any, subdomain: str) -> Optional[str]:
        safe_name = subdomain.replace(".", "_").replace(":", "_")
        filepath = self.output_dir / f"{safe_name}.png"

        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                driver.get(url)
                # Brief wait for page to render
                import time

                time.sleep(2)
                driver.save_screenshot(str(filepath))
                return str(filepath)
            except Exception:
                continue

        return None
