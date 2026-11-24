"""Parser and compressor unit tests. Run: python tests/test_converter.py"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cloudflare_gateway.compressor import (  # noqa: E402
    can_promote_to,
    compress,
    synthesize_regex,
)
from cloudflare_gateway.converter import (  # noqa: E402
    convert_to_allow_list,
    convert_to_block_list,
    extract_domains,
)


def _block(text: str) -> list[str]:
    return convert_to_block_list(text, exception_domains=set())


def test_hosts_comment() -> None:
    assert _block("0.0.0.0 ads.example.com # comment") == ["ads.example.com"]


def test_non_local_hosts_skipped() -> None:
    assert _block("110.43.121.13 bigota.d.miui.com") == []


def test_adblock() -> None:
    assert _block("||ads.example.com^") == ["ads.example.com"]


def test_exception_not_blocked() -> None:
    exceptions: set[str] = set()
    blocked = convert_to_block_list("@@||drive.example.com^\n||ads.example.com^", exceptions)
    assert "drive.example.com" not in blocked
    assert "drive.example.com" in exceptions
    assert blocked == ["ads.example.com"]


def test_bare_at_exception() -> None:
    exceptions: set[str] = set()
    convert_to_block_list("@@good.example.com^", exceptions)
    assert "good.example.com" in exceptions


def test_cosmetic_skipped() -> None:
    assert _block("example.com##.ad") == []


def test_localhost_skipped() -> None:
    assert _block("0.0.0.0 localhost") == []


def test_wildcard() -> None:
    assert _block("*.adtech.de") == ["adtech.de"]


def test_dnsmasq() -> None:
    assert _block("address=/ads.example.com/0.0.0.0") == ["ads.example.com"]


def test_rpz() -> None:
    assert _block("tracker.example.com CNAME .") == ["tracker.example.com"]


def test_unbound() -> None:
    assert _block('local-zone: "ads.example.com." always_nxdomain') == ["ads.example.com"]


def test_parent_collapse() -> None:
    got = _block("ads.example.com\nfoo.ads.example.com\nexample.com")
    assert got == ["example.com"]


def test_glued_newline() -> None:
    # Two files joined with newline must not produce ads.comtracker.io
    text = "ads.example.com\ntracker.io"
    got = _block(text)
    assert "ads.example.comtracker.io" not in got
    assert "ads.example.com" in got
    assert "tracker.io" in got


def test_allow_parser() -> None:
    assert convert_to_allow_list("0.0.0.0 keep.example.com") == ["keep.example.com"]


def test_regex_line_collected() -> None:
    regex: set[str] = set()
    extract_domains(r"^ad[0-9]+\.tracker\.com$", set(), regex_patterns=regex)
    assert any("tracker" in p for p in regex)


def test_compress_fits() -> None:
    domains, regex, stats, uncovered = compress(
        [f"ads{i}.example.com" for i in range(10)] + ["example.com"],
        allow_domains=[],
    )
    assert domains == ["example.com"]
    assert stats["after_parent_collapse"] == 1
    assert uncovered == []


def test_synthesize_regex() -> None:
    overflow = [f"n{i}.tracker.evil.test" for i in range(20)]
    pats = synthesize_regex(overflow)
    assert pats
    assert r"tracker\.evil\.test" in pats[0]


def test_never_promote_google() -> None:
    assert can_promote_to("google.com") is False
    assert can_promote_to("co.uk") is False
    assert can_promote_to("doubleclick.net") is True


def test_ads_kept_before_threat() -> None:
    ads = [f"ad{i}.tracker.test" for i in range(5)]
    threat = [f"mal{i}.evil.test" for i in range(50)]
    # Tiny budget via monkeypatch is heavy; just ensure ads survive collapse
    # when mixed with a parentable threat pile.
    domains, _regex, stats, _unc = compress(
        ads + threat,
        allow_domains=[],
        priority_domains=ads,
        secondary_domains=threat,
    )
    assert stats["ads_priority"] == 5
    # ads.tracker.test parent collapse may keep tracker.test or the ads
    assert any("tracker.test" == d or d.endswith(".tracker.test") or d in ads for d in domains)


if __name__ == "__main__":
    failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok  {name}")
            except Exception as exc:
                failed += 1
                print(f" FAIL {name}: {exc}")
    raise SystemExit(failed)
