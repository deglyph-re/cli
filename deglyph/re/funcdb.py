# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Function-level fingerprinting against a signature corpus.

Where `re/fingerprint` identifies a whole library from version strings, this
identifies an individual recovered function: a stripped `sub_<va>` matched to
`inflate` from `zlib 1.2.13`. Each corpus entry is a `FuncSignature` (the
content-addressed identity from `re/funcsig`, labeled with the library, version,
and architecture it came from); `identify_functions` signs every function in an
image and looks it up, exact-first then fuzzy.

Public names: `FuncSignature`, `FuncMatch`, `FuncDB`, `load_func_db`,
`identify_functions`, `bundled_path`, `BUNDLED_VERSION`.

The corpus is grown by `scripts/build_funcdb.py` (run in CI over many well-known
programs) and shipped as `deglyph/data/funcdb.json`. A match is a heuristic:
two unrelated functions can share a normalized shape, so report it as a
candidate identification to confirm, never as proof. An empty corpus means no
catalog entry, never "self-contained".
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field

from ..core.image import Image
from .funcsig import FuncSig, func_sig, similarity

log = logging.getLogger(__name__)

# Default Jaccard floor for a fuzzy function identification (matches bindiff).
_MIN_SIMILARITY = 0.85

# Schema version of the bundled corpus document; bumped on a breaking shape change.
BUNDLED_VERSION = 1


@dataclass(slots=True)
class FuncSignature:
    """One catalogued function: its identity plus where it came from.

    `exact` and `ngrams` are the `re/funcsig` identity; `lib` / `version` /
    `ecosystem` / `arch` record the build it was harvested from so a match can be
    attributed and an architecture mismatch rejected.
    """

    name: str
    lib: str
    version: str | None
    ecosystem: str
    arch: str
    exact: str
    n_insns: int
    ngrams: frozenset[str] = field(default_factory=frozenset)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "lib": self.lib,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "arch": self.arch,
            "exact": self.exact,
            "n_insns": self.n_insns,
            "ngrams": sorted(self.ngrams),
        }

    @staticmethod
    def from_dict(d: dict) -> FuncSignature | None:
        try:
            return FuncSignature(
                name=str(d["name"]),
                lib=str(d["lib"]),
                version=(None if d.get("version") is None else str(d["version"])),
                ecosystem=str(d.get("ecosystem", "generic")),
                arch=str(d.get("arch", "")),
                exact=str(d["exact"]),
                n_insns=int(d.get("n_insns", 0)),
                ngrams=frozenset(str(g) for g in d.get("ngrams", ())),
            )
        except (KeyError, TypeError, ValueError):
            return None


@dataclass(slots=True)
class FuncMatch:
    """A recovered function identified against the corpus.

    `confidence` is "high" for an exact content match, "medium" for a fuzzy one;
    `similarity` is 1.0 / the Jaccard score; `evidence` states the basis.
    """

    va: int
    current_name: str
    lib: str
    func: str
    version: str | None
    ecosystem: str
    confidence: str
    similarity: float
    evidence: str


class FuncDB:
    """An indexed function-signature corpus: exact lookup plus per-arch fuzzy scan."""

    def __init__(self, signatures: list[FuncSignature] | None = None):
        self.signatures: list[FuncSignature] = []
        self._by_exact: dict[tuple[str, str], FuncSignature] = {}
        self._by_arch: dict[str, list[FuncSignature]] = {}
        for s in signatures or []:
            self.add(s)

    def add(self, s: FuncSignature) -> None:
        self.signatures.append(s)
        # An exact hash plus arch is the identity key; later entries win a clash.
        self._by_exact[(s.arch, s.exact)] = s
        self._by_arch.setdefault(s.arch, []).append(s)

    def __len__(self) -> int:
        return len(self.signatures)

    def match(
        self, sig: FuncSig, arch: str, *, min_similarity: float = _MIN_SIMILARITY
    ) -> tuple[FuncSignature, str, float] | None:
        """Best corpus entry for `sig` on `arch`: (signature, confidence, score)."""
        exact = self._by_exact.get((arch, sig.exact))
        if exact is not None:
            return exact, "high", 1.0
        best: FuncSignature | None = None
        best_score = 0.0
        for cand in self._by_arch.get(arch, ()):
            lo, hi = sorted((sig.n_insns or 1, cand.n_insns or 1))
            # Jaccard cannot exceed the size ratio; skip an obvious mismatch.
            if hi and lo / hi < min_similarity:
                continue
            score = similarity(sig, _as_funcsig(cand))
            if score > best_score:
                best, best_score = cand, score
        if best is not None and best_score >= min_similarity:
            return best, "medium", best_score
        return None


def _as_funcsig(s: FuncSignature) -> FuncSig:
    """Adapt a corpus entry to the `FuncSig` shape `similarity` consumes."""
    return FuncSig(va=0, exact=s.exact, ngrams=s.ngrams, n_insns=s.n_insns)


def bundled_path() -> str:
    """Filesystem path of the corpus shipped with the package."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, os.pardir, "data", "funcdb.json")


def _read_corpus(path: str) -> list[FuncSignature]:
    """Parse a corpus JSON file into signatures; a bad file degrades to empty."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return []
    raw = doc.get("functions", []) if isinstance(doc, dict) else []
    out: list[FuncSignature] = []
    for entry in raw:
        sig = FuncSignature.from_dict(entry) if isinstance(entry, dict) else None
        if sig is not None:
            out.append(sig)
    return out


def load_func_db(path: str | None = None) -> FuncDB:
    """Load the bundled corpus, then merge a user corpus file over it.

    Best-effort: a missing or malformed file contributes nothing rather than
    raising, so `--func-signatures` and the shipped catalog are advisory.
    """
    db = FuncDB(_read_corpus(bundled_path()))
    if path:
        for s in _read_corpus(path):
            db.add(s)
    return db


def identify_functions(
    image: Image, db: FuncDB, *, min_similarity: float = _MIN_SIMILARITY
) -> list[FuncMatch]:
    """Identify each non-import function in `image` against the corpus.

    Run function discovery first if the binary is stripped, so the recovered
    `sub_*` functions are present to identify. Returns one `FuncMatch` per
    function the corpus recognizes, sorted by address.
    """
    arch = image.arch.value
    if not db.signatures:
        return []
    out: list[FuncMatch] = []
    for f in image.funcs:
        if f.kind == "import":
            continue
        sig = func_sig(image, f.va)
        if sig is None:
            continue
        hit = db.match(sig, arch, min_similarity=min_similarity)
        if hit is None:
            continue
        cand, confidence, score = hit
        label = f"{cand.lib} {cand.version}" if cand.version else cand.lib
        basis = (
            "exact content match" if confidence == "high" else f"{score:.0%} similar"
        )
        out.append(
            FuncMatch(
                va=f.va,
                current_name=f.display,
                lib=cand.lib,
                func=cand.name,
                version=cand.version,
                ecosystem=cand.ecosystem,
                confidence=confidence,
                similarity=score,
                evidence=f"{basis} to {cand.name} ({label})",
            )
        )
    return out
