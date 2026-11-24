"""High-level synchronization of Cloudflare lists and rules."""
from __future__ import annotations

from typing import Optional, Sequence

from . import state
from .api import (
    create_list,
    create_rule,
    delete_list,
    delete_rule,
    update_list,
    update_rule,
)
from .compressor import compress, lists_needed, write_coverage_artifacts
from .config import (
    ALLOW_PREFIX,
    BLOCK_PREFIX,
    DOMAINS_PER_LIST,
    ENABLE_SNI_FILTER,
    MAX_REGEX_EXPR_CHARS,
    MAX_REGEX_PER_RULE,
    MAX_TOTAL_LISTS,
    REGEX_RULE_PREFIX,
)
from .http_client import HTTPException, NotFoundException
from .log import fatal, info, warn
from .sources import AllowDomainConverter, BlockDomainConverter


class CloudflareManager:
    """Reconcile local domain sources with Cloudflare Gateway resources."""

    def __init__(self, cache: state.Cache) -> None:
        self.cache = cache
        self.block_list_name = f"[{BLOCK_PREFIX}]"
        self.block_rule_name = f"[{BLOCK_PREFIX}] Block Ads"
        self.block_sni_rule_name = f"[{BLOCK_PREFIX}] Block Ads (SNI)"
        self.allow_list_name = f"[{ALLOW_PREFIX}]"
        self.allow_rule_name = f"[{ALLOW_PREFIX}] Allow"
        self.allow_sni_rule_name = f"[{ALLOW_PREFIX}] Allow (SNI)"
        self.regex_rule_prefix = f"[{REGEX_RULE_PREFIX}"
        self.regex_sni_prefix = f"[{BLOCK_PREFIX}] Block Ads (SNI regex"

    def _sync_rule(
        self,
        list_ids: Sequence[str],
        rule_name: str,
        rule_action: str,
        rule_priority: int,
        filters: Optional[Sequence[str]] = None,
        traffic_field: str = "dns.domains",
        traffic: Optional[str] = None,
    ) -> None:
        if not list_ids and not traffic:
            info(f"[·] No lists/traffic for {rule_name} — deleting rule if present")
            self._delete_rule_by_name(rule_name)
            return

        current_rules = state.get_current_rules(self.cache, rule_name)
        existing_rule = next(
            (rule for rule in current_rules if rule["name"] == rule_name), None
        )
        existing_list_ids = state.extract_list_ids(existing_rule)
        needs_update = True
        if existing_rule and traffic is None:
            needs_update = set(list_ids) != existing_list_ids
        elif existing_rule and traffic is not None:
            needs_update = (existing_rule.get("traffic") or "") != traffic

        if existing_rule and not needs_update:
            warn(f"[·] Skipping rule update (unchanged): {rule_name}")
            return

        kwargs = dict(
            action=rule_action,
            priority=rule_priority,
            filters=filters,
            traffic_field=traffic_field,
        )

        if existing_rule:
            try:
                updated = update_rule(
                    rule_name,
                    existing_rule["id"],
                    list_ids,
                    traffic=traffic,
                    **kwargs,
                )
                info(f"[~] Updated rule: {updated['name']}")
                self.cache["rules"] = [
                    rule
                    for rule in self.cache["rules"]
                    if rule["id"] != existing_rule["id"]
                ]
                self.cache["rules"].append(updated)
            except NotFoundException:
                warn(
                    f"[·] Rule {rule_name} ({existing_rule['id']}) missing on "
                    f"Cloudflare — evicting from cache and recreating"
                )
                self.cache["rules"] = [
                    rule
                    for rule in self.cache["rules"]
                    if rule["id"] != existing_rule["id"]
                ]
                rule = create_rule(rule_name, list_ids, traffic=traffic, **kwargs)
                info(f"[+] Recreated rule: {rule['name']}")
                self.cache["rules"].append(rule)
        else:
            rule = create_rule(rule_name, list_ids, traffic=traffic, **kwargs)
            info(f"[+] Created rule: {rule['name']}")
            self.cache["rules"].append(rule)
        state.save_cache(self.cache)

    def _delete_rule_by_name(self, rule_name: str) -> None:
        current_rules = state.get_current_rules(self.cache, rule_name)
        for rule in current_rules:
            try:
                delete_rule(rule["id"])
                info(f"[−] Deleted rule: {rule['name']}")
            except NotFoundException:
                warn(f"[·] Rule {rule['name']} already gone on Cloudflare — skipping")
            self.cache["rules"] = [
                item for item in self.cache["rules"] if item["id"] != rule["id"]
            ]
            state.save_cache(self.cache)

    def _delete_rules_by_prefix(self, prefix: str) -> None:
        current_rules = state.get_current_rules(self.cache, prefix)
        for rule in current_rules:
            if not rule["name"].startswith(prefix) and prefix not in rule["name"]:
                continue
            try:
                delete_rule(rule["id"])
                info(f"[−] Deleted rule: {rule['name']}")
            except NotFoundException:
                warn(f"[·] Rule {rule['name']} already gone — skipping")
            self.cache["rules"] = [
                item for item in self.cache["rules"] if item["id"] != rule["id"]
            ]
        state.save_cache(self.cache)

    def _delete_by_prefix(self, list_name_prefix: str, rule_name: str) -> None:
        self._delete_rule_by_name(rule_name)
        current_lists = state.get_current_lists(self.cache, list_name_prefix)
        for lst in current_lists:
            try:
                delete_list(lst["id"])
                info(f"[−] Deleted list: {lst['name']}")
            except NotFoundException:
                warn(f"[·] List {lst['name']} already gone on Cloudflare — skipping")
            self.cache["lists"] = [
                item for item in self.cache.get("lists", []) if item["id"] != lst["id"]
            ]
            self.cache.get("mapping", {}).pop(lst["id"], None)
            state.save_cache(self.cache)
        state.save_cache(self.cache)

    def _chunk_regex(self, patterns: Sequence[str], field: str) -> list[str]:
        chunks: list[list[str]] = []
        current: list[str] = []
        size = 0
        for pat in patterns:
            clause = f'{field} matches "{pat}"'
            extra = len(clause) + (4 if current else 0)
            if current and (
                len(current) >= MAX_REGEX_PER_RULE
                or size + extra > MAX_REGEX_EXPR_CHARS
            ):
                chunks.append(current)
                current = []
                size = 0
            current.append(pat)
            size += extra
        if current:
            chunks.append(current)
        return [
            " or ".join(f'{field} matches "{p}"' for p in chunk) for chunk in chunks
        ]

    def _sync_regex_rules(
        self,
        patterns: Sequence[str],
        name_prefix: str,
        field: str,
        priority: int,
        filters: Optional[Sequence[str]] = None,
    ) -> None:
        expressions = self._chunk_regex(patterns, field) if patterns else []
        # Drop stale regex rules whose index is beyond the new set.
        existing = [
            r
            for r in self.cache.get("rules", [])
            if r.get("name", "").startswith(name_prefix)
        ]
        keep_names = {f"{name_prefix} {i:03d}" for i in range(1, len(expressions) + 1)}
        for rule in existing:
            if rule["name"] not in keep_names:
                try:
                    delete_rule(rule["id"])
                    info(f"[−] Deleted stale regex rule: {rule['name']}")
                except NotFoundException:
                    pass
                self.cache["rules"] = [
                    item for item in self.cache["rules"] if item["id"] != rule["id"]
                ]
        for index, expr in enumerate(expressions, start=1):
            try:
                self._sync_rule(
                    [],
                    f"{name_prefix} {index:03d}",
                    rule_action="block",
                    rule_priority=priority,
                    filters=filters,
                    traffic_field=field,
                    traffic=expr,
                )
            except (HTTPException, ValueError) as exc:
                warn(
                    f"Regex rule {name_prefix} {index:03d} rejected by Cloudflare "
                    f"({exc}). Lists still stand; this pattern was skipped."
                )
        state.save_cache(self.cache)

    def _sync_lists(
        self,
        domains: Sequence[str],
        list_name_prefix: str,
        rule_name: str,
        rule_action: str,
        rule_priority: int,
        sni_rule_name: Optional[str] = None,
    ) -> list[str]:
        cached_hash, cached_domains = state.get_cached_domain_state(
            self.cache, list_name_prefix
        )
        current_hash = state.compute_domain_hash(domains)
        if cached_hash is not None and cached_hash == current_hash:
            info(
                f"[·] No changes detected for {list_name_prefix} "
                f"({len(domains)} domains) — skipping all lists"
            )
            current_lists = state.get_current_lists(self.cache, list_name_prefix)
            list_ids = [lst["id"] for lst in current_lists]
            self._sync_rule(list_ids, rule_name, rule_action, rule_priority)
            if sni_rule_name:
                self._sync_rule(
                    list_ids,
                    sni_rule_name,
                    rule_action,
                    rule_priority,
                    filters=["l4"],
                    traffic_field="net.sni.domains",
                )
            return list_ids

        to_add, to_remove = state.get_domain_diff(domains, cached_domains)
        if cached_hash is None:
            info(f"[+] First sync for {list_name_prefix} — creating {len(domains)} domains")
        else:
            info(
                f"[⟳] {list_name_prefix} changed: "
                f"+{len(to_add)} / -{len(to_remove)} domains"
            )
        state.set_cached_domain_state(self.cache, list_name_prefix, domains)
        state.save_cache(self.cache)

        current_lists = state.get_current_lists(self.cache, list_name_prefix)
        list_name_to_id = {lst["name"]: lst["id"] for lst in current_lists}
        reverse_map = state.get_cached_reverse_mapping(self.cache, list_name_prefix)
        if reverse_map:
            info(
                f"[↓] Using reverse mapping ({len(reverse_map)} entries) "
                f"for surgical sync"
            )
            new_list_ids = self._sync_lists_surgical(
                domains, current_lists, to_add, to_remove, reverse_map, list_name_prefix
            )
        else:
            info("[⟳] No reverse mapping yet — falling back to full per-list sync")
            new_list_ids = self._sync_lists_full(
                domains, current_lists, list_name_to_id, list_name_prefix
            )

        new_reverse = state.build_reverse_mapping(
            self.cache, new_list_ids, list_name_prefix
        )
        state.set_cached_reverse_mapping(self.cache, list_name_prefix, new_reverse)

        self._sync_rule(new_list_ids, rule_name, rule_action, rule_priority)
        if sni_rule_name:
            self._sync_rule(
                new_list_ids,
                sni_rule_name,
                rule_action,
                rule_priority,
                filters=["l4"],
                traffic_field="net.sni.domains",
            )
        state.save_cache(self.cache)
        return new_list_ids

    def _sync_lists_surgical(
        self,
        domains: Sequence[str],
        current_lists: list[dict],
        to_add: set[str],
        to_remove: set[str],
        reverse_map: dict[str, str],
        list_name_prefix: str,
    ) -> list[str]:
        list_removes: dict[str, set[str]] = {}
        for domain in to_remove:
            list_id = reverse_map.get(domain)
            if list_id is not None:
                list_removes.setdefault(list_id, set()).add(domain)
        remaining_add = list(to_add)
        new_list_ids: list[str] = []
        for lst in current_lists:
            list_id = lst["id"]
            removes = list_removes.get(list_id, set())
            current_values = set(self.cache.get("mapping", {}).get(list_id, []))
            chunk = current_values - removes
            if not chunk:
                try:
                    delete_list(list_id)
                    info(f"[−] Deleted list: {lst['name']} (no longer needed)")
                except NotFoundException:
                    warn(f"[·] List {lst['name']} already gone on Cloudflare — skipping")
                self.cache["lists"] = [
                    item for item in self.cache["lists"] if item["id"] != list_id
                ]
                self.cache["mapping"].pop(list_id, None)
                state.save_cache(self.cache)
                continue
            new_items: list[str] = []
            if len(chunk) < DOMAINS_PER_LIST and remaining_add:
                needed_items = DOMAINS_PER_LIST - len(chunk)
                new_items = remaining_add[:needed_items]
                remaining_add = remaining_add[needed_items:]
                chunk.update(new_items)
            if removes or new_items:
                try:
                    update_list(list_id, removes, set(new_items))
                    info(
                        f"[~] Updated list: {lst['name']} "
                        f"| Added {len(new_items)}, Removed {len(removes)} "
                        f"| Total: {len(chunk)}"
                    )
                    self.cache["mapping"][list_id] = sorted(chunk)
                except NotFoundException:
                    warn(
                        f"[·] List {lst['name']} ({list_id}) missing on Cloudflare "
                        f"— evicting from cache and recreating"
                    )
                    self.cache["lists"] = [
                        item for item in self.cache["lists"] if item["id"] != list_id
                    ]
                    self.cache["mapping"].pop(list_id, None)
                    created = create_list(lst["name"], sorted(chunk))
                    info(f"[+] Recreated list: {created['name']} with {len(chunk)} domains")
                    self.cache["lists"].append(created)
                    self.cache["mapping"][created["id"]] = sorted(chunk)
                    list_id = created["id"]
                state.save_cache(self.cache)
            else:
                warn(f"[·] Skipped (no changes): {lst['name']} | Total: {len(chunk)}")
            new_list_ids.append(list_id)

        for list_id in list(new_list_ids):
            if not remaining_add:
                break
            current_values = set(self.cache.get("mapping", {}).get(list_id, []))
            if len(current_values) >= DOMAINS_PER_LIST:
                continue
            needed_items = DOMAINS_PER_LIST - len(current_values)
            new_items = remaining_add[:needed_items]
            remaining_add = remaining_add[needed_items:]
            current_values.update(new_items)
            try:
                update_list(list_id, set(), set(new_items))
                info(
                    f"[+] Filled list: {len(new_items)} domains "
                    f"| Total: {len(current_values)}"
                )
                self.cache["mapping"][list_id] = sorted(current_values)
            except NotFoundException:
                warn(f"[·] List {list_id} missing — skipping fill")
            state.save_cache(self.cache)

        existing_indexes = []
        for lst in current_lists:
            try:
                existing_indexes.append(int(lst["name"].split("-")[-1]))
            except (ValueError, IndexError):
                pass
        next_index = max(existing_indexes + [0]) + 1
        while remaining_add:
            needed_items = min(DOMAINS_PER_LIST, len(remaining_add))
            new_items = remaining_add[:needed_items]
            remaining_add = remaining_add[needed_items:]
            list_name = f"{list_name_prefix} - {next_index:03d}"
            created = create_list(list_name, new_items)
            info(f"[+] Created list: {created['name']} with {len(new_items)} domains")
            self.cache["lists"].append(created)
            self.cache["mapping"][created["id"]] = new_items
            state.save_cache(self.cache)
            new_list_ids.append(created["id"])
            next_index += 1
        return new_list_ids

    def _sync_lists_full(
        self,
        domains: Sequence[str],
        current_lists: list[dict],
        list_name_to_id: dict[str, str],
        list_name_prefix: str,
    ) -> list[str]:
        list_id_to_domains: dict[str, set[str]] = {}
        for lst in current_lists:
            list_id_to_domains[lst["id"]] = set(
                state.get_list_items_cached(self.cache, lst["id"])
            )
        domain_to_list_id = {
            domain: list_id
            for list_id, doms in list_id_to_domains.items()
            for domain in doms
        }
        remaining_domains = set(domains) - set(domain_to_list_id.keys())
        existing_indexes = sorted(
            [int(name.split("-")[-1]) for name in list_name_to_id.keys()]
        )
        needed_lists = (len(domains) + DOMAINS_PER_LIST - 1) // DOMAINS_PER_LIST
        all_indexes = set(range(1, max(existing_indexes + [needed_lists]) + 1))
        new_list_ids: list[str] = []
        for index in sorted(all_indexes):
            list_name = f"{list_name_prefix} - {index:03d}"
            if list_name not in list_name_to_id:
                if remaining_domains:
                    needed_items = min(DOMAINS_PER_LIST, len(remaining_domains))
                    new_items = list(remaining_domains)[:needed_items]
                    remaining_domains.difference_update(new_items)
                    created = create_list(list_name, new_items)
                    info(
                        f"[+] Created list: {created['name']} "
                        f"with {len(new_items)} domains"
                    )
                    self.cache["lists"].append(created)
                    self.cache["mapping"][created["id"]] = new_items
                    state.save_cache(self.cache)
                    new_list_ids.append(created["id"])
                continue
            list_id = list_name_to_id[list_name]
            current_values = list_id_to_domains[list_id]
            remove_items = current_values - set(domains)
            chunk = current_values - remove_items
            new_items: list[str] = []
            if len(chunk) < DOMAINS_PER_LIST and remaining_domains:
                needed_items = DOMAINS_PER_LIST - len(chunk)
                new_items = list(remaining_domains)[:needed_items]
                chunk.update(new_items)
                remaining_domains.difference_update(new_items)
            if not chunk:
                try:
                    delete_list(list_id)
                    info(f"[−] Deleted list: {list_name} (no longer needed)")
                except NotFoundException:
                    warn(f"[·] List {list_name} already gone on Cloudflare — skipping")
                self.cache["lists"] = [
                    item for item in self.cache["lists"] if item["id"] != list_id
                ]
                self.cache["mapping"].pop(list_id, None)
                state.save_cache(self.cache)
                continue
            if remove_items or new_items:
                try:
                    update_list(list_id, remove_items, new_items)
                    info(
                        f"[~] Updated list: {list_name} "
                        f"| Added {len(new_items)}, Removed {len(remove_items)} "
                        f"| Total: {len(chunk)}"
                    )
                    self.cache["mapping"][list_id] = list(chunk)
                except NotFoundException:
                    warn(
                        f"[·] List {list_name} ({list_id}) missing on Cloudflare "
                        f"— evicting from cache and recreating"
                    )
                    self.cache["lists"] = [
                        item for item in self.cache["lists"] if item["id"] != list_id
                    ]
                    self.cache["mapping"].pop(list_id, None)
                    created = create_list(list_name, list(chunk))
                    info(
                        f"[+] Recreated list: {created['name']} "
                        f"with {len(chunk)} domains"
                    )
                    self.cache["lists"].append(created)
                    self.cache["mapping"][created["id"]] = list(chunk)
                    list_id = created["id"]
                state.save_cache(self.cache)
            else:
                warn(f"[·] Skipped (no changes): {list_name} | Total: {len(chunk)}")
            new_list_ids.append(list_id)
        return new_list_ids

    def update_resources(self) -> None:
        info("=== [1/2] Processing BLOCK domains ===")
        block_converter = BlockDomainConverter()
        domains_to_block = block_converter.process_urls()
        info("=== [2/2] Processing ALLOW domains ===")
        domains_to_allow = AllowDomainConverter().process_urls(
            extra_domains=block_converter.auto_whitelist_domains
        )

        info("=== Compressing to Cloudflare DOMAIN quota ===")
        domains_to_block, regex_patterns, stats, uncovered = compress(
            domains_to_block,
            domains_to_allow,
            priority_domains=block_converter.priority_domains,
            secondary_domains=block_converter.secondary_domains,
        )
        # Source-file regex (Pi-hole / uBlock) is often PCRE, not RE2.
        # Uploading it will 400 the Gateway rule and abort the job. Keep it
        # off the wire; synthesized patterns are RE2-safe by construction.
        if block_converter.regex_patterns:
            info(
                f"Ignoring {len(block_converter.regex_patterns)} source regex "
                f"line(s) (PCRE). Using {len(regex_patterns)} synthesized RE2 "
                f"pattern(s) only."
            )
        write_coverage_artifacts(stats, uncovered)
        info(f"Compressor stats: {stats}")

        block_lists_needed = lists_needed(len(domains_to_block))
        allow_lists_needed = lists_needed(len(domains_to_allow))
        total_lists_needed = block_lists_needed + allow_lists_needed
        info(
            f"Lists needed → Block: {block_lists_needed}, "
            f"Allow: {allow_lists_needed}, "
            f"Total: {total_lists_needed} / {MAX_TOTAL_LISTS}; "
            f"regex patterns: {len(regex_patterns)}"
        )
        if total_lists_needed > MAX_TOTAL_LISTS:
            fatal(
                f"Total lists needed ({total_lists_needed}) exceeds the "
                f"Cloudflare Gateway free limit of {MAX_TOTAL_LISTS} lists. "
                f"Reduce your adlists or whitelist sources."
            )

        info("=== Syncing BLOCK lists & rule ===")
        self._sync_lists(
            domains_to_block,
            self.block_list_name,
            self.block_rule_name,
            rule_action="block",
            rule_priority=1000,
            sni_rule_name=self.block_sni_rule_name if ENABLE_SNI_FILTER else None,
        )
        info("=== Syncing ALLOW lists & rule ===")
        self._sync_lists(
            domains_to_allow,
            self.allow_list_name,
            self.allow_rule_name,
            rule_action="allow",
            rule_priority=999,
            sni_rule_name=self.allow_sni_rule_name if ENABLE_SNI_FILTER else None,
        )
        info("=== Syncing supplemental REGEX rules ===")
        self._sync_regex_rules(
            regex_patterns,
            f"[{BLOCK_PREFIX}] Block Ads (regex)",
            field="dns.fqdn",
            priority=1000,
        )
        if ENABLE_SNI_FILTER:
            self._sync_regex_rules(
                regex_patterns,
                f"[{BLOCK_PREFIX}] Block Ads (SNI regex)",
                field="net.sni",
                priority=1000,
                filters=["l4"],
            )
        else:
            self._sync_regex_rules(
                [],
                f"[{BLOCK_PREFIX}] Block Ads (SNI regex)",
                field="net.sni",
                priority=1000,
                filters=["l4"],
            )
        info("=== Done ===")

    def delete_resources(self) -> None:
        info("=== Deleting BLOCK resources ===")
        self._delete_rule_by_name(self.block_sni_rule_name)
        self._delete_rule_by_name(self.allow_sni_rule_name)
        self._sync_regex_rules([], f"[{BLOCK_PREFIX}] Block Ads (regex)", "dns.fqdn", 1000)
        self._sync_regex_rules(
            [], f"[{BLOCK_PREFIX}] Block Ads (SNI regex)", "net.sni", 1000, ["l4"]
        )
        self._delete_by_prefix(self.block_list_name, self.block_rule_name)
        info("=== Deleting ALLOW resources ===")
        self._delete_by_prefix(self.allow_list_name, self.allow_rule_name)
