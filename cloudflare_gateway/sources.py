"""Collect domains from remote adlists/whitelists and local dynamic files."""
from __future__ import annotations

import os
from configparser import ConfigParser, Error as ConfigParserError
from pathlib import Path
from typing import Optional

from .config import (
    ADLIST_FILE,
    DYNAMIC_BLACKLIST_FILE,
    DYNAMIC_WHITELIST_FILE,
    WHITELIST_FILE,
)
from .converter import convert_to_allow_list, convert_to_block_list
from .http_client import (
    HTTPException,
    RateLimitException,
    get_session,
    parse_retry_after,
    retry,
    retry_config,
)
from .log import info, warn

_DOWNLOAD_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; Cloudflare-Gateway-DNS-Filter/2.1)"}

# URL / INI-section markers. Ads+telemetry fill DOMAIN slots FIRST; threat second.
_ADS_MARKERS = (
    "ads",
    "privacy",
    "pro.plus",
    "pro-plus",
    "telemetry",
    "tracking",
    "easylist",
    "easyprivacy",
    "adguard",
    "ublock",
    "stevenblack",
    "annoyance",
)
_THREAT_MARKERS = ("tif", "threat", "malware", "phishing", "urlhaus", "abuse", "c2")


class BaseDomainConverter:
    """Shared logic for downloading and reading list sources."""

    def read_urls_from_file(self, filename: Path | str) -> list[str]:
        path = Path(filename)
        if not path.exists():
            return []
        content = path.read_text(encoding="utf-8")
        try:
            # interpolation=None: URLs containing '%' must not raise.
            parser = ConfigParser(interpolation=None)
            parser.read_string(content)
        except ConfigParserError:
            return [
                line.strip()
                for line in content.splitlines()
                if line.strip() and not line.startswith("#")
            ]
        return [
            parser.get(section, option)
            for section in parser.sections()
            for option in parser.options(section)
        ]

    def read_url_records(self, file_path: Path | str) -> list[tuple[str, str]]:
        """Return ``[(url, section_name), ...]`` so the compressor can prioritize."""
        path = Path(file_path)
        if not path.exists():
            return []
        content = path.read_text(encoding="utf-8")
        try:
            parser = ConfigParser(interpolation=None)
            parser.read_string(content)
        except ConfigParserError:
            return [
                (line.strip(), "")
                for line in content.splitlines()
                if line.strip() and not line.startswith("#")
            ]
        return [
            (parser.get(section, option), section)
            for section in parser.sections()
            for option in parser.options(section)
        ]

    def read_urls_from_env(self, env_var: str) -> list[str]:
        raw = os.getenv(env_var, "")
        return [url.strip() for url in raw.split() if url.strip()]

    def read_urls(self, env_var: str, file_path: Path | str) -> list[str]:
        # Env last so Actions variables can append without editing the fork.
        return self.read_urls_from_file(file_path) + self.read_urls_from_env(env_var)

    @retry(**retry_config)
    def download_file(
        self, url: str, timeout: int = 60, max_redirects: int = 5
    ) -> str:
        response = get_session().request(
            "GET",
            url,
            headers=dict(_DOWNLOAD_HEADERS),
            timeout=timeout,
            follow_redirects=True,
            max_redirects=max_redirects,
        )
        if response.status_code != 200:
            error_message = (
                f"Failed to download file from {url}, "
                f"status code: {response.status_code}"
            )
            warn(error_message)
            if response.status_code == 429:
                raise RateLimitException(
                    error_message,
                    retry_after=parse_retry_after(response.get_header("Retry-After")),
                )
            raise HTTPException(error_message)
        data = response.text
        info(f"Downloaded file from {url}. File size: {len(data)}")
        return data

    def download_all(self, urls: list[str]) -> tuple[str, dict[str, str]]:
        """Fetch every URL. Returns (joined_text, {url: body} for successes)."""
        fetched: dict[str, str] = {}
        for url in urls:
            try:
                fetched[url] = self.download_file(url)
            except Exception as exc:
                warn(f"Skipping list {url}: {exc}")
        return "\n".join(fetched.values()), fetched


class BlockDomainConverter(BaseDomainConverter):
    """Build the block domain list.

    Whitelist subtraction for *enforcement* is NOT done here — the Allow rule
    in Cloudflare Gateway takes precedence. The compressor may still subtract
    allow names from the uploaded *block list* so they do not waste quota.
    """

    def __init__(self) -> None:
        self.adlist_urls = self.read_urls("ADLIST_URLS", ADLIST_FILE)
        self.auto_whitelist_domains: set[str] = set()
        self.regex_patterns: set[str] = set()
        self.priority_domains: set[str] = set()  # ads / telemetry
        self.secondary_domains: set[str] = set()  # malware / TIF

    def process_urls(self) -> list[str]:
        block_content, fetched = self.download_all(self.adlist_urls)
        dynamic_blacklist = os.getenv("DYNAMIC_BLACKLIST", "")
        if dynamic_blacklist:
            block_content += "\n" + dynamic_blacklist
        else:
            block_content += "\n" + _read_file(DYNAMIC_BLACKLIST_FILE)

        self.auto_whitelist_domains.clear()
        self.regex_patterns.clear()
        domains = convert_to_block_list(
            block_content,
            exception_domains=self.auto_whitelist_domains,
            regex_patterns=self.regex_patterns,
        )
        info(
            f"Number of auto-whitelisted exceptions: "
            f"{len(self.auto_whitelist_domains)}"
        )
        info(f"Number of source regex patterns: {len(self.regex_patterns)}")

        records = self.read_url_records(ADLIST_FILE)
        url_section = {url: section for url, section in records}

        def _blob(markers: tuple[str, ...]) -> str:
            parts: list[str] = []
            for url, body in fetched.items():
                hay = f"{url} {url_section.get(url, '')}".lower()
                if any(m in hay for m in markers):
                    parts.append(body)
            return "\n".join(parts)

        ads_text = _blob(_ADS_MARKERS)
        dyn = os.getenv("DYNAMIC_BLACKLIST", "") or _read_file(DYNAMIC_BLACKLIST_FILE)
        if dyn.strip():
            ads_text = ads_text + "\n" + dyn
        if ads_text.strip():
            self.priority_domains = set(
                convert_to_block_list(ads_text, exception_domains=set())
            )
            info(f"Priority (ads/telemetry) domains: {len(self.priority_domains)}")
        threat_text = _blob(_THREAT_MARKERS)
        if threat_text.strip():
            self.secondary_domains = set(
                convert_to_block_list(threat_text, exception_domains=set())
            )
            info(f"Secondary (threat) domains: {len(self.secondary_domains)}")
        return domains


class AllowDomainConverter(BaseDomainConverter):
    """Build the allow domain list."""

    def __init__(self) -> None:
        self.whitelist_urls = self.read_urls("WHITELIST_URLS", WHITELIST_FILE)

    def process_urls(self, extra_domains: Optional[set[str]] = None) -> list[str]:
        white_content, _ = self.download_all(self.whitelist_urls)
        dynamic_whitelist = os.getenv("DYNAMIC_WHITELIST", "")
        if dynamic_whitelist:
            white_content += "\n" + dynamic_whitelist
        else:
            white_content += "\n" + _read_file(DYNAMIC_WHITELIST_FILE)
        domains = set(convert_to_allow_list(white_content))
        if extra_domains:
            domains |= extra_domains
            info(
                f"Added {len(extra_domains)} auto-whitelisted "
                f"@@|| exceptions to the Allow list"
            )
        return sorted(domains)


def _read_file(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")
