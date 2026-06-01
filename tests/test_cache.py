# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""On-disk analysis cache keyed by file hash."""

from __future__ import annotations

from deglyph import cache


def test_roundtrip_hit_and_miss(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    digest = "a" * 64
    assert cache.cache_get(digest, "strings") is None
    cache.cache_put(digest, "strings", [{"va": "0x1000", "text": "hi"}])
    assert cache.cache_get(digest, "strings") == [{"va": "0x1000", "text": "hi"}]
    # a different kind for the same binary is a separate slot
    assert cache.cache_get(digest, "xrefs") is None


def test_different_digest_misses(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    cache.cache_put("a" * 64, "strings", ["x"])
    # a changed binary (different hash) does not see the old entry
    assert cache.cache_get("b" * 64, "strings") is None


def test_none_digest_is_always_a_miss(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    cache.cache_put(None, "strings", ["x"])
    assert cache.cache_get(None, "strings") is None


def test_version_mismatch_is_a_miss(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    digest = "c" * 64
    cache.cache_put(digest, "strings", ["x"])
    monkeypatch.setattr(cache, "CACHE_VERSION", cache.CACHE_VERSION + 1)
    # an entry written by an older deglyph is ignored, not mis-read
    assert cache.cache_get(digest, "strings") is None


def test_disabled_by_env(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    digest = "d" * 64
    cache.cache_put(digest, "strings", ["x"])
    monkeypatch.setenv("DEGLYPH_NO_CACHE", "1")
    assert cache.cache_get(digest, "strings") is None
    cache.cache_put(digest, "other", ["y"])
    monkeypatch.delenv("DEGLYPH_NO_CACHE")
    # nothing was written while disabled
    assert cache.cache_get(digest, "other") is None


def test_file_sha256_and_clear(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    f = tmp_path / "bin"
    f.write_bytes(b"\x90\x90\xc3")
    digest = cache.file_sha256(str(f))
    assert digest and len(digest) == 64
    # an identical content hashes the same; a changed byte does not
    g = tmp_path / "bin2"
    g.write_bytes(b"\x90\x90\xc3")
    assert cache.file_sha256(str(g)) == digest
    assert cache.file_sha256(str(tmp_path / "nope")) is None

    cache.cache_put(digest, "k", [1, 2, 3])
    assert cache.cache_get(digest, "k") == [1, 2, 3]
    assert cache.clear_cache() >= 1
    assert cache.cache_get(digest, "k") is None
