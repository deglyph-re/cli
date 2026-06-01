# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""Tests for function-level fingerprinting (re/funcdb)."""

from __future__ import annotations

import json

from deglyph import scan
from deglyph.re.funcdb import (
    FuncDB,
    FuncSignature,
    identify_functions,
    load_func_db,
)
from deglyph.re.funcsig import func_sig

# mov eax,1; mov ecx,2; add eax,ecx; xor edx,edx; sub eax,ecx; imul; or; and; ret
_A = bytes.fromhex("b801000000b90200000001c831d229c80fafc109d021c8c3")
# one localized edit of `_A`
_A_MOD = bytes.fromhex("b801000000b90200000001c8ba0300000029c80fafc109d021c8c3")


def _sig_for(code_image, blob: bytes, **over) -> FuncSignature:
    img = code_image(blob)
    s = func_sig(img, 0x1000)
    assert s is not None
    fields = dict(
        name="inflate",
        lib="zlib",
        version="1.2.13",
        ecosystem="generic",
        arch=img.arch.value,
        exact=s.exact,
        n_insns=s.n_insns,
        ngrams=s.ngrams,
    )
    fields.update(over)
    return FuncSignature(**fields)


def test_bundled_corpus_loads(code_image):
    # The shipped corpus is valid and (until CI populates it) empty.
    db = load_func_db()
    assert isinstance(db, FuncDB)
    assert len(db) == 0


def test_exact_identification(code_image):
    db = FuncDB([_sig_for(code_image, _A)])
    matches = identify_functions(code_image(_A), db)
    assert len(matches) == 1
    m = matches[0]
    assert m.func == "inflate" and m.lib == "zlib" and m.version == "1.2.13"
    assert m.confidence == "high"
    assert m.similarity == 1.0


def test_fuzzy_identification(code_image):
    db = FuncDB([_sig_for(code_image, _A)])
    matches = identify_functions(code_image(_A_MOD), db, min_similarity=0.1)
    assert len(matches) == 1
    m = matches[0]
    assert m.confidence == "medium"
    assert 0.0 < m.similarity < 1.0


def test_arch_mismatch_is_not_matched(code_image):
    db = FuncDB([_sig_for(code_image, _A, arch="arm64")])
    # the image is x86-64, so an arm64 corpus entry must not match
    assert identify_functions(code_image(_A), db) == []


def test_empty_corpus_matches_nothing(code_image):
    assert identify_functions(code_image(_A), FuncDB([])) == []


def test_load_merges_user_corpus(code_image, tmp_path):
    sig = _sig_for(code_image, _A)
    p = tmp_path / "corpus.json"
    p.write_text(
        json.dumps({"funcdb_version": 1, "generated": "", "functions": [sig.to_dict()]})
    )
    db = load_func_db(str(p))
    assert len(db) == 1
    matches = identify_functions(code_image(_A), db)
    assert matches and matches[0].func == "inflate"


def test_malformed_corpus_degrades_to_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ not valid json")
    db = load_func_db(str(p))
    assert len(db) == 0


def test_scan_identify_emits_lib_function(code_image, tmp_path):
    sig = _sig_for(code_image, _A)
    corpus = tmp_path / "corpus.json"
    corpus.write_text(
        json.dumps({"funcdb_version": 1, "generated": "", "functions": [sig.to_dict()]})
    )
    img = code_image(_A)
    findings = scan.scan_image(
        img,
        hardening=False,
        fingerprint=False,
        identify=True,
        func_signatures=str(corpus),
    )
    rules = {f.rule for f in findings}
    assert "lib/function" in rules
    hit = next(f for f in findings if f.rule == "lib/function")
    assert "inflate" in hit.message and hit.category == "fact"
