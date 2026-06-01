# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Per-binary annotation persistence (sidecar JSON)."""

from __future__ import annotations

from deglyph.store import Annotations, list_sessions, load, sidecar_path


def test_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    a = Annotations(path="/some/binary.dll")
    a.names[0x1000] = "parse_header"
    a.comments[0x1000] = "validates the magic"
    a.bookmarks.add(0x2000)
    a.save()

    b = load("/some/binary.dll")
    assert b.names == {0x1000: "parse_header"}
    assert b.comments == {0x1000: "validates the magic"}
    assert b.bookmarks == {0x2000}


def test_missing_sidecar_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    a = load("/never/saved.bin")
    assert a.names == {} and a.comments == {} and a.bookmarks == set()
    assert a.chats == {} and a.is_empty()


def test_list_sessions_skips_missing_files(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    f1 = tmp_path / "a.bin"
    f1.write_bytes(b"x")
    f2 = tmp_path / "b.bin"
    f2.write_bytes(b"y")
    Annotations(path=str(f1), names={0x10: "x"}).save()
    Annotations(path=str(f2), bookmarks={0x20}).save()
    # deleted
    Annotations(path=str(tmp_path / "gone.bin"), names={0x1: "z"}).save()

    paths = {s.path for s in list_sessions()}
    # the missing file is not offered
    assert paths == {str(f1), str(f2)}


def test_list_sessions_empty_when_none(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    assert list_sessions() == []


def test_chats_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    convo = [
        {"role": "user", "content": "what is this?"},
        {"role": "assistant", "content": [{"type": "text", "text": "a crc16"}]},
    ]
    a = Annotations(path="/some/binary.dll")
    a.chats[0x1400010A0] = convo
    # a chat counts as work worth saving
    assert not a.is_empty()
    a.save()

    b = load("/some/binary.dll")
    # int VA key, content preserved
    assert b.chats == {0x1400010A0: convo}


def test_corrupt_sidecar_is_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    p = sidecar_path("/x/y.bin")
    # ensure dir usable
    tmp_path.joinpath(p.rsplit("/", 1)[-1].rsplit("\\", 1)[-1])
    import os

    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write("{ not valid json")
    # tolerated, not raised
    assert load("/x/y.bin").names == {}


def test_nonhex_key_is_tolerated(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    p = sidecar_path("/x/z.bin")
    import os

    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        # valid JSON, invalid key
        fh.write('{"names": {"not-hex": "f"}}')
    # degrades to empty, does not raise
    assert load("/x/z.bin").names == {}


def test_keys_are_hex_strings(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    a = Annotations(path="/b.bin", names={0x140001000: "f"})
    assert a.to_dict()["names"] == {"0x140001000": "f"}


def test_view_state_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    a = Annotations(path="/v.bin")
    a.view = {"filter": "enc", "tab": "tab-analysis", "selected_va": 0x1000}
    # a saved view is work worth reopening on its own
    assert not a.is_empty()
    a.save()
    b = load("/v.bin")
    assert b.view == {"filter": "enc", "tab": "tab-analysis", "selected_va": 0x1000}


def test_view_state_sanitizes_bad_fields(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    import json
    import os

    p = sidecar_path("/v2.bin")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "binary": "/v2.bin",
                "view": {"filter": 5, "tab": "tab-info", "selected_va": "0x2000"},
            },
            fh,
        )
    a = load("/v2.bin")
    # a non-string filter is dropped; a hex-string selected_va is parsed to int
    assert a.view == {"tab": "tab-info", "selected_va": 0x2000}


def test_view_state_non_dict_is_dropped(tmp_path, monkeypatch):
    monkeypatch.setenv("DEGLYPH_STORE_DIR", str(tmp_path))
    import json
    import os

    p = sidecar_path("/v3.bin")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"binary": "/v3.bin", "view": "not-a-dict"}, fh)
    assert load("/v3.bin").view == {}


def test_portable_roundtrip_is_path_independent():
    a = Annotations(path="/a/bin")
    a.names[0x1000] = "parse_header"
    a.comments[0x10] = "validates magic"
    a.bookmarks.add(0x20)
    a.view = {"tab": "tab-info", "filter": "enc"}
    p = a.to_portable()
    # the portable form carries no binary path and is versioned
    assert "binary" not in p
    assert p["deglyph_project_version"] == 1

    b = Annotations.from_portable("/other/machine/bin", p)
    assert b.path == "/other/machine/bin"
    assert b.names == {0x1000: "parse_header"}
    assert b.comments == {0x10: "validates magic"}
    assert b.bookmarks == {0x20}
    assert b.view == {"tab": "tab-info", "filter": "enc"}
    # chats are deliberately not exported
    assert b.chats == {}


def test_from_portable_tolerates_junk():
    a = Annotations.from_portable("/x/y.bin", {"names": {"zzz": "v", "0x40": "ok"}})
    # an unparseable hex key is dropped, a valid one kept
    assert a.names == {0x40: "ok"}
    # a non-dict payload yields empty annotations, not an error
    assert Annotations.from_portable("/x/y.bin", "garbage").is_empty()
