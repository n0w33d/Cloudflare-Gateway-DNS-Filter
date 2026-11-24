"""Parse blocklists and whitelists into clean, de-duplicated domain sets.

Supported input styles (auto-detected per line):
  * hosts          0.0.0.0 ads.example.com / 127.0.0.1 / ::1
  * plain domains  ads.example.com
  * Adblock/uBO    ||ads.example.com^   @@||good.example.com^
  * wildcard       *.ads.example.com    *ads.example.com
  * dnsmasq        address=/ads.example.com/0.0.0.0
  * unbound        local-zone: "ads.example.com." always_nxdomain
  * RPZ            ads.example.com CNAME .
  * Pi-hole regex  ^ad[0-9]+\\.tracker\\.com$   (collected separately)
"""
from __future__ import annotations

from typing import Optional

from .config import (
    DOMAIN_PATTERN,
    DNSMASQ_PATTERN,
    IP_PATTERN,
    REGEX_LINE_PATTERN,
    REPLACE_PATTERN,
    RPZ_PATTERN,
    UNBOUND_PATTERN,
)
from .log import info

_LOCAL_BLOCK_IPS = ("127.0.0.1", "0.0.0.0", "::1")


def convert_to_block_list(
    block_content: str,
    exception_domains: Optional[set[str]] = None,
    regex_patterns: Optional[set[str]] = None,
) -> list[str]:
    """Convert mixed-format blocklists into a sorted Cloudflare domain list."""
    block_domains: set[str] = set()
    extract_domains(
        block_content,
        block_domains,
        exception_domains,
        regex_patterns=regex_patterns,
    )
    info(f"Number of blocked domains: {len(block_domains)}")
    final_domains = sorted(remove_redundant_subdomains(block_domains))
    info(f"Number of final block domains (parents collapsed): {len(final_domains)}")
    return final_domains


def convert_to_allow_list(white_content: str) -> list[str]:
    """Convert a whitelist into a sorted list of Cloudflare domains."""
    white_domains: set[str] = set()
    extract_domains(white_content, white_domains)
    info(f"Number of whitelisted domains: {len(white_domains)}")
    final_domains = sorted(white_domains)
    info(f"Number of final allow domains: {len(final_domains)}")
    return final_domains


def _normalize_domain(raw: str) -> Optional[str]:
    domain = raw.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if domain.startswith("*"):
        domain = domain[1:].lstrip(".")
    if "." not in domain:
        return None
    try:
        domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return None
    if not DOMAIN_PATTERN.match(domain) or IP_PATTERN.match(domain):
        return None
    return domain


def extract_domains(
    content: str,
    domains: set[str],
    exception_domains: Optional[set[str]] = None,
    regex_patterns: Optional[set[str]] = None,
) -> None:
    """Extract valid domains (and optional regex) from mixed-format ``content``."""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!", "/", ";")):
            continue
        # Browser cosmetic / scriptlet rules are not DNS names.
        if "##" in line or "#@#" in line or "#$#" in line or "#%#" in line:
            continue

        is_exception = line.lower().startswith("@@")

        dnsmasq = DNSMASQ_PATTERN.match(line)
        if dnsmasq:
            domain = _normalize_domain(dnsmasq.group(1))
            if domain:
                if is_exception and exception_domains is not None:
                    exception_domains.add(domain)
                else:
                    domains.add(domain)
            continue

        unbound = UNBOUND_PATTERN.match(line)
        if unbound:
            domain = _normalize_domain(unbound.group(1))
            if domain:
                domains.add(domain)
            continue

        rpz = RPZ_PATTERN.match(line)
        if rpz:
            domain = _normalize_domain(rpz.group(2))
            if domain:
                domains.add(domain)
            continue

        parts = line.split()
        if len(parts) >= 2 and IP_PATTERN.match(parts[0]):
            if parts[0] not in _LOCAL_BLOCK_IPS:
                continue
        elif len(parts) >= 2 and ":" in parts[0] and parts[0] not in _LOCAL_BLOCK_IPS:
            # Non-local IPv6 hosts entry — skip, do not treat the name as a block.
            continue

        # Bare regex filter (Pi-hole / AdGuard Home style), not a hostname.
        candidate_for_regex = line.lower()
        if (
            regex_patterns is not None
            and not is_exception
            and not line.startswith(("||", "0.0.0.0", "127.0.0.1"))
            and REGEX_LINE_PATTERN.search(line.split("#")[0])
            and "://" not in line
        ):
            pattern = line.split("#")[0].strip()
            if pattern.startswith("/") and pattern.endswith("/"):
                pattern = pattern[1:-1]
            if pattern:
                regex_patterns.add(pattern)
            continue

        cleaned_line = line.lower().split("#")[0].split("^")[0].replace("\r", "")
        if cleaned_line.startswith("@@"):
            cleaned_line = cleaned_line[2:]
            is_exception = True
        domain = REPLACE_PATTERN.sub("", cleaned_line, count=1)
        domain = _normalize_domain(domain)
        if not domain:
            continue
        if is_exception:
            if exception_domains is not None:
                exception_domains.add(domain)
        else:
            domains.add(domain)


def remove_redundant_subdomains(domains: set[str]) -> set[str]:
    """Drop domains already covered by a parent in the set.

    Cloudflare ``dns.domains`` matches the QNAME *and its parents*, so listing
    ``example.com`` already blocks ``ads.example.com``.
    """
    top_level_domains: set[str] = set()
    for domain in domains:
        parts = domain.split(".")
        is_covered = any(
            ".".join(parts[index:]) in domains for index in range(1, len(parts))
        )
        if not is_covered:
            top_level_domains.add(domain)
    return top_level_domains
