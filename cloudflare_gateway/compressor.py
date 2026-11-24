"""Fit a large domain feed into Cloudflare Gateway's DOMAIN-list quota.

Cloudflare standard/free Gateway:
  * Custom DOMAIN lists are an *account* quota (this repo defaults to
    300 lists x 1,000 names — confirm in your dashboard; some orgs are 100).
  * ``dns.domains`` already matches parents, so subdomain collapse is free.
  * Regex is NOT a list type — it is a short string inside a policy expression.

Priority when the budget is tight (operator requirement):
  1. Ads + telemetry
  2. Malicious / threat intel
  3. Everything else

Never silently drop: leftovers are written to uncovered.txt + coverage_report.json.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Optional

from .config import (
    ALLOW_LIST_HEADROOM,
    COVERAGE_REPORT_FILE,
    DOMAINS_PER_LIST,
    MAX_REGEX_PATTERNS,
    MAX_TOTAL_LISTS,
    PROTECTED_APEXES,
    PUBLIC_SUFFIXES,
    REGEX_MIN_GROUP,
    UNCOVERED_FILE,
)
from .converter import remove_redundant_subdomains
from .log import info, warn

_NUMBERED_HOST = re.compile(
    r"^([a-z]{1,12}?)(\d{1,6})\.(.+)$", re.IGNORECASE
)


def lists_needed(count: int) -> int:
    if count <= 0:
        return 0
    return (count + DOMAINS_PER_LIST - 1) // DOMAINS_PER_LIST


def domain_budget(allow_count: int) -> int:
    """How many block DOMAIN entries we can still upload."""
    allow_lists = lists_needed(allow_count)
    remaining_lists = max(0, MAX_TOTAL_LISTS - allow_lists - ALLOW_LIST_HEADROOM)
    return remaining_lists * DOMAINS_PER_LIST


def _escape_re(domain: str) -> str:
    return domain.replace(".", r"\.").replace("-", r"\-")


def _parent_of(domain: str) -> Optional[str]:
    parts = domain.split(".")
    if len(parts) < 3:
        return None
    return ".".join(parts[1:])


def can_promote_to(parent: str) -> bool:
    """Refuse parents that would nuke a public suffix or a too-big zone."""
    if not parent or "." not in parent:
        return False
    if parent in PROTECTED_APEXES or parent in PUBLIC_SUFFIXES:
        return False
    labels = parent.split(".")
    # two-label parent of a public suffix, e.g. promoting foo.co.uk → co.uk
    if parent in PUBLIC_SUFFIXES:
        return False
    if len(labels) == 2 and labels[1] in PUBLIC_SUFFIXES:
        return False
    # never promote to a 1-label TLD
    if len(labels) < 2:
        return False
    return True


def _covered_by(domain: str, keepers: set[str]) -> bool:
    parts = domain.split(".")
    return any(".".join(parts[i:]) in keepers for i in range(len(parts)))


def _promote_busy_parents(domains: set[str], budget: int, max_rounds: int = 4000) -> set[str]:
    """Replace the largest *safe* sibling groups with their parent until we fit."""
    current = set(domains)
    rounds = 0
    while len(current) > budget and rounds < max_rounds:
        rounds += 1
        children_of: dict[str, list[str]] = defaultdict(list)
        for domain in current:
            parent = _parent_of(domain)
            if parent and can_promote_to(parent):
                children_of[parent].append(domain)
        if not children_of:
            break
        parent, kids = max(children_of.items(), key=lambda kv: len(kv[1]))
        if len(kids) < 2:
            break
        for kid in kids:
            current.discard(kid)
        current.add(parent)
        current = remove_redundant_subdomains(current)
    if rounds >= max_rounds:
        warn(f"Parent promotion hit {max_rounds} rounds — stopping to avoid timeout")
    return current


def synthesize_regex(overflow: Iterable[str]) -> list[str]:
    """Turn leftover hostnames into a few parent-covering / numbered RE2 patterns."""
    overflow = list(overflow)
    groups: dict[str, int] = defaultdict(int)
    numbered: dict[str, set[str]] = defaultdict(set)
    for domain in overflow:
        m = _NUMBERED_HOST.match(domain)
        if m:
            prefix, _n, rest = m.group(1), m.group(2), m.group(3)
            numbered[f"{prefix.lower()}#.{rest}"].add(domain)
        parent = _parent_of(domain)
        if parent and can_promote_to(parent):
            groups[parent] += 1

    patterns: list[str] = []
    # Numbered hosts first — high coverage per character.
    for key, hosts in sorted(numbered.items(), key=lambda kv: len(kv[1]), reverse=True):
        if len(hosts) < REGEX_MIN_GROUP:
            continue
        prefix, rest = key.split("#.", 1)
        patterns.append(rf"^{_escape_re(prefix)}[0-9]+\.{_escape_re(rest)}$")
        if len(patterns) >= MAX_REGEX_PATTERNS:
            return patterns

    ranked = sorted(groups.items(), key=lambda kv: kv[1], reverse=True)
    for parent, n in ranked:
        if n < REGEX_MIN_GROUP:
            break
        patterns.append(rf"^(.+\.)?{_escape_re(parent)}$")
        if len(patterns) >= MAX_REGEX_PATTERNS:
            break
    return patterns


def _regex_covers(domain: str, patterns: list[str]) -> bool:
    """Cheap structural check (not a full RE2 engine) for coverage stats."""
    for pat in patterns:
        # ^(.+\.)?parent$  or  ^prefix[0-9]+\.rest$
        if pat.startswith("^(.+\\.)?") and pat.endswith("$"):
            parent = (
                pat[len("^(.+\\.)?") : -1]
                .replace(r"\.", ".")
                .replace(r"\-", "-")
            )
            if domain == parent or domain.endswith("." + parent):
                return True
        elif "[0-9]+" in pat:
            # numbered: skip full match; treat rest suffix
            rest = pat.split("[0-9]+\\.", 1)[-1].rstrip("$").replace(r"\.", ".")
            if domain.endswith("." + rest) or domain.endswith(rest):
                return True
    return False


def compress(
    block_domains: Iterable[str],
    allow_domains: Iterable[str],
    priority_domains: Optional[Iterable[str]] = None,
    secondary_domains: Optional[Iterable[str]] = None,
) -> tuple[list[str], list[str], dict[str, int], list[str]]:
    """Return ``(domains_to_upload, regex_patterns, stats, uncovered)``.

    ``priority_domains`` = ads/telemetry (fill DOMAIN slots first).
    ``secondary_domains`` = malware/TIF (fill whatever slots remain).
    """
    allow = set(allow_domains)
    block = {d for d in block_domains if d not in allow}
    ads = {d for d in (priority_domains or set()) if d not in allow}
    threat = {d for d in (secondary_domains or set()) if d not in allow}

    collapsed = remove_redundant_subdomains(block)
    budget = domain_budget(len(allow))
    stats: dict[str, int] = {
        "raw_block": len(set(block_domains)),
        "after_allow_subtract": len(block),
        "after_parent_collapse": len(collapsed),
        "budget": budget,
        "ads_priority": len(ads),
        "threat_secondary": len(threat),
        "promoted": 0,
        "regex": 0,
        "uncovered": 0,
        "kept": 0,
        "coverage_pct": 100,
    }
    info(
        f"Compressor: {stats['raw_block']} raw → {len(collapsed)} after collapse; "
        f"DOMAIN budget {budget}; ads-first={len(ads)} threat={len(threat)}"
    )

    if len(collapsed) <= budget:
        stats["kept"] = len(collapsed)
        return sorted(collapsed), [], stats, []

    ads_keep = remove_redundant_subdomains(ads) & collapsed
    threat_keep = (remove_redundant_subdomains(threat) & collapsed) - ads_keep
    other = collapsed - ads_keep - threat_keep

    if len(ads_keep) > budget:
        warn(
            f"Ads/telemetry alone ({len(ads_keep)}) exceed budget {budget}; "
            f"promoting safe parents (never google.com / public suffixes)"
        )
        ads_keep = _promote_busy_parents(ads_keep, budget)
        threat_keep = set()
        other = set()

    remaining = max(0, budget - len(ads_keep))
    if len(threat_keep) > remaining:
        threat_keep = _promote_busy_parents(threat_keep, remaining)
        other = set()
    remaining = max(0, budget - len(ads_keep) - len(threat_keep))
    ranked_other = sorted(other, key=lambda d: (d.count("."), len(d), d))
    other_keep = set(ranked_other[:remaining])

    kept = ads_keep | threat_keep | other_keep
    overflow: set[str] = set()
    # One more promotion pass on the union if we are still over (should be rare).
    if len(kept) > budget:
        kept = _promote_busy_parents(kept, budget)

    if len(kept) > budget:
        extra = sorted(kept, key=lambda d: (d.count("."), len(d), d), reverse=True)
        overflow.update(extra[budget:])
        kept = set(extra[:budget])

    overflow = (collapsed - kept) | overflow
    overflow = {d for d in overflow if not _covered_by(d, kept)}

    regex = synthesize_regex(overflow)
    still_uncovered = sorted(
        d for d in overflow if not _covered_by(d, kept) and not _regex_covers(d, regex)
    )

    original = set(block_domains) - allow
    covered = sum(
        1
        for d in original
        if _covered_by(d, kept) or _regex_covers(d, regex)
    )
    stats["kept"] = len(kept)
    stats["regex"] = len(regex)
    stats["uncovered"] = len(still_uncovered)
    stats["promoted"] = max(0, stats["after_parent_collapse"] - len(kept))
    if original:
        stats["coverage_pct"] = int(100 * covered / len(original))
    info(
        f"Compressor result: keep {len(kept)} DOMAIN rows, {len(regex)} regex, "
        f"{len(still_uncovered)} uncovered, coverage {stats['coverage_pct']}%"
    )
    if still_uncovered:
        warn(
            f"{len(still_uncovered)} FQDNs have no list parent and no regex. "
            f"See {UNCOVERED_FILE.name} — shrink adlist.ini or allow more parent collapse."
        )
    return sorted(kept), regex, stats, still_uncovered


def write_coverage_artifacts(
    stats: dict[str, int],
    uncovered: list[str],
    report_path: Path = COVERAGE_REPORT_FILE,
    uncovered_path: Path = UNCOVERED_FILE,
) -> None:
    report_path.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    if uncovered:
        uncovered_path.write_text("\n".join(uncovered) + "\n", encoding="utf-8")
    elif uncovered_path.exists():
        uncovered_path.write_text("", encoding="utf-8")
    info(f"Wrote {report_path.name} and {uncovered_path.name}")
