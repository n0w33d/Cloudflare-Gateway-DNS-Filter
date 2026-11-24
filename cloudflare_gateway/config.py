"""Project configuration: paths, constants, regexes and credentials."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"
LISTS_DIR = PROJECT_ROOT / "lists"
ADLIST_FILE = LISTS_DIR / "adlist.ini"
WHITELIST_FILE = LISTS_DIR / "whitelist.ini"
DYNAMIC_BLACKLIST_FILE = LISTS_DIR / "dynamic_blacklist.txt"
DYNAMIC_WHITELIST_FILE = LISTS_DIR / "dynamic_whitelist.txt"
CACHE_FILE = PROJECT_ROOT / "cloudflare_cache.json"
COVERAGE_REPORT_FILE = PROJECT_ROOT / "coverage_report.json"
UNCOVERED_FILE = PROJECT_ROOT / "uncovered.txt"

# Do not collapse/promote into these zones (would break the internet).
PROTECTED_APEXES = frozenset(
    {
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googleusercontent.com",
        "youtube.com",
        "gvt1.com",
        "gvt2.com",
        "microsoft.com",
        "windows.com",
        "live.com",
        "office.com",
        "office365.com",
        "microsoftonline.com",
        "msn.com",
        "apple.com",
        "icloud.com",
        "mzstatic.com",
        "cdn-apple.com",
        "cloudflare.com",
        "cloudflare-dns.com",
        "one.one.one.one",
        "amazon.com",
        "amazonaws.com",
        "aws.amazon.com",
        "facebook.com",
        "fbcdn.net",
        "whatsapp.com",
        "instagram.com",
        "meta.com",
        "apple-dns.net",
        "akamaiedge.net",
        "akamai.net",
        "cloudfront.net",
        "github.com",
        "githubusercontent.com",
        "wikipedia.org",
        "cloudflare.net",
    }
)
# Multi-part public suffixes — never promote *to* these.
PUBLIC_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "ne.jp",
        "or.jp",
        "com.br",
        "net.br",
        "com.mx",
        "co.za",
        "co.in",
        "com.cn",
        "co.kr",
        "com.tw",
        "co.nz",
        "org.nz",
        "github.io",
        "herokuapp.com",
        "azurewebsites.net",
        "s3.amazonaws.com",
        "appspot.com",
        "pages.dev",
        "workers.dev",
    }
)

# Cloudflare Gateway standard/free: 300 lists, 1,000 exact DOMAIN entries each.
# Regex does NOT consume list quota — it lives in Gateway policy expressions.
MAX_TOTAL_LISTS = 300
DOMAINS_PER_LIST = 1000
MAX_DOMAIN_ENTRIES = MAX_TOTAL_LISTS * DOMAINS_PER_LIST  # 300,000 theoretical

# Leave headroom so an allow-list expansion cannot push us over 300 lists.
ALLOW_LIST_HEADROOM = 5

# Supplemental regex rules (policy expressions, not DOMAIN lists).
MAX_REGEX_PATTERNS = 200
MAX_REGEX_PER_RULE = 15
MAX_REGEX_EXPR_CHARS = 3500
REGEX_MIN_GROUP = 8  # collapse this many sibling leftovers into one regex

BLOCK_PREFIX = "AdBlock-DNS-Filters"
ALLOW_PREFIX = "AdAllow-DNS-Filters"
REGEX_RULE_PREFIX = "AdBlock-DNS-Filters] Block Ads (regex"

CLOUDFLARE_HOST = "api.cloudflare.com"
CLOUDFLARE_API_PATH = "/client/v4/accounts/{account_id}/gateway"

ENABLE_SNI_FILTER = (os.getenv("ENABLE_SNI_FILTER") or "").strip().lower() in (
    "1",
    "true",
    "yes",
)

_PLACEHOLDER_TOKEN = "your CF_API_TOKEN value"
_PLACEHOLDER_IDENTIFIER = "your CF_IDENTIFIER value"


class ConfigError(Exception):
    """Raised when required configuration (Cloudflare credentials) is missing."""


def load_dotenv(path: Path = ENV_FILE) -> dict[str, str]:
    """Parse a minimal ``.env`` file into a mapping."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if len(value) >= 2 and value.startswith("<") and value.endswith(">"):
            value = value[1:-1]
        if key:
            values[key] = value
    return values


_DOTENV = load_dotenv()


def _get(name: str) -> Optional[str]:
    return os.getenv(name) or _DOTENV.get(name)


CF_API_TOKEN = _get("CF_API_TOKEN")
CF_IDENTIFIER = _get("CF_IDENTIFIER")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")


def require_credentials() -> None:
    if (
        not CF_API_TOKEN
        or CF_API_TOKEN == _PLACEHOLDER_TOKEN
        or not CF_IDENTIFIER
        or CF_IDENTIFIER == _PLACEHOLDER_IDENTIFIER
    ):
        raise ConfigError(
            "Missing Cloudflare credentials. Set CF_API_TOKEN and CF_IDENTIFIER "
            "as environment variables or in the .env file."
        )


IDS_PATTERN = re.compile(r"\$([a-f0-9-]+)")
IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
REPLACE_PATTERN = re.compile(
    r"(^([0-9.]+|[0-9a-fA-F:.]+)\s+|^(\|\||@@\|\||@@|\*\.|\*))"
)
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$"
)
REGEX_LINE_PATTERN = re.compile(r"[\\\[\]()|?+{}]")
DNSMASQ_PATTERN = re.compile(
    r"^(?:address|server|local)=/([^/]+)/", re.IGNORECASE
)
UNBOUND_PATTERN = re.compile(
    r'^local-zone:\s*"([^"]+)"', re.IGNORECASE
)
RPZ_PATTERN = re.compile(
    r"^(\*\.)?([A-Za-z0-9.-]+)\s+(?:CNAME|NXDOMAIN|NODATA|PASSTHRU)\b",
    re.IGNORECASE,
)
