# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Static binary scanner for CI: hardening posture, secrets, libs, risky imports, drift.

Reads a loaded `Image` (never executes it) and reports findings as a flat list,
which `to_sarif` / `to_text` render. Six checks:

  scan_hardening   ASLR / DEP / CFG / canaries / PIE / RELRO / fortify / signed
  scan_secrets     provider-token regexes, credential keywords, and high entropy
  scan_imports     imported APIs that grant exec / injection / network capability
  scan_fingerprint third-party libraries linked into the binary (re/fingerprint)
  scan_cve         CVEs against detected library versions via osv.dev (opt-in)
  diff_baseline    functions and imports present here but not in a baseline build

Public: Finding, scan_image, scan_file, iter_targets, to_sarif, to_text, RULES.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass

from .core.image import Arch, Image, load_image
from .re.strings import string_runs

# rule id -> (default SARIF level, one-line description)
RULES: dict[str, tuple[str, str]] = {
    "secret/private-key": ("error", "Private key material embedded in the binary"),
    "secret/aws-access-key": ("error", "AWS access key id"),
    "secret/github-token": ("error", "GitHub access token"),
    "secret/slack-token": ("error", "Slack token"),
    "secret/google-api-key": ("error", "Google API key"),
    "secret/jwt": ("warning", "JSON Web Token"),
    "secret/credential-keyword": ("warning", "String labeled as a credential"),
    "secret/high-entropy": ("note", "High-entropy string (possible secret)"),
    "import/process-exec": ("warning", "Imports a process / command execution API"),
    "import/code-injection": ("warning", "Imports a code-injection API"),
    "import/memory-protect": ("note", "Imports a memory-protection-change API"),
    "import/dynamic-load": ("note", "Imports a dynamic code-loading API"),
    "import/network": ("note", "Imports a network API"),
    "import/anti-debug": ("note", "Imports an anti-debugging API"),
    "diff/added-import": ("warning", "Imported API added since the baseline build"),
    "diff/added-function": ("note", "Function added since the baseline build"),
    "diff/removed-function": ("note", "Function removed since the baseline build"),
    "harden/no-aslr": ("warning", "ASLR is disabled (DYNAMIC_BASE / PIE missing)"),
    "harden/no-dep": ("warning", "DEP / NX is disabled (data pages remain executable)"),
    "harden/no-cfg": ("note", "Control Flow Guard is not enabled"),
    "harden/no-stack-canary": ("warning", "Stack canaries are not present"),
    "harden/no-pie": ("warning", "Binary is not position independent (PIE)"),
    "harden/no-relro": ("warning", "RELRO is disabled (GOT is writable at runtime)"),
    "harden/partial-relro": ("note", "Partial RELRO only (BIND_NOW not set)"),
    "harden/no-fortify": ("note", "FORTIFY_SOURCE checked variants not detected"),
    "harden/unsigned": ("note", "Binary carries no code signature"),
    "harden/no-high-entropy-va": ("note", "64-bit binary lacks high-entropy ASLR"),
    "harden/no-safeseh": ("note", "SafeSEH handler table is absent (PE32 only)"),
    "harden/no-bti-pac": ("note", "ARM BTI / PAC hints are not advertised"),
    "lib/detected": ("note", "Third-party library identified by fingerprint"),
    "cve/known": ("error", "Known CVE against a detected library version"),
}

_LEVEL_RANK = {"note": 0, "warning": 1, "error": 2}


@dataclass(slots=True)
class Finding:
    rule: str
    level: str
    message: str
    # human location: a VA, "import", or "diff"
    where: str
    # file offset, when known (for SARIF regions)
    off: int | None = None
    length: int = 0


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _char_classes(s: str) -> int:
    return sum(
        (
            any(c.isupper() for c in s),
            any(c.islower() for c in s),
            any(c.isdigit() for c in s),
            any(not c.isalnum() for c in s),
        )
    )


# --- secrets ----------------------------------------------------------------

# High-precision provider formats, then a keyword rule for labeled credentials.
_SECRET_RES: list[tuple[str, re.Pattern]] = [
    ("secret/private-key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("secret/aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("secret/github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("secret/slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("secret/google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    (
        "secret/jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"
        ),
    ),
    (
        "secret/credential-keyword",
        re.compile(
            r"(?i)(?<![a-z])"
            r"(?:api[_-]?key|secret(?:[_-]?key)?|passw(?:or)?d"
            r"|access[_-]?key|client[_-]?secret|auth[_-]?token|bearer)"
            r"(?![a-z])"
        ),
    ),
]


def scan_secrets(image: Image, data: bytes, *, entropy: bool = False) -> list[Finding]:
    """Find embedded credentials in the binary's string table.

    Provider regexes and the credential-keyword rule are always on. The
    entropy catch-all is opt-in: on native binaries it fires on build paths and
    mangled symbol names, so it is off by default to keep the report precise.
    """
    out: list[Finding] = []
    for off, _enc, text in string_runs(data, min_len=6):
        matched = False
        for rule, rx in _SECRET_RES:
            if rx.search(text):
                out.append(_secret_finding(image, rule, off, text))
                matched = True
                break
        if matched or not entropy:
            continue
        # Entropy catch-all over opaque, blob-like tokens (no path/symbol noise).
        for tok in text.split():
            if _looks_high_entropy(tok):
                out.append(_secret_finding(image, "secret/high-entropy", off, tok))
                break
    return out


def _looks_high_entropy(tok: str) -> bool:
    # skip paths and URLs
    if len(tok) < 24 or any(c in tok for c in "/\\:"):
        return False
    alnum = sum(c.isalnum() for c in tok)
    # mangled symbols carry many separators
    if alnum / len(tok) < 0.85:
        return False
    return _char_classes(tok) >= 3 and _entropy(tok) >= 4.3


def _secret_finding(image: Image, rule: str, off: int, text: str) -> Finding:
    va = _off_to_va(image, off)
    snippet = text if len(text) <= 60 else text[:57] + "..."
    level, desc = RULES[rule]
    where = f"{va:#x}" if va is not None else f"@{off:#x}"
    return Finding(rule, level, f"{desc}: {snippet!r}", where, off, len(text))


# --- imports ----------------------------------------------------------------

# Imported-symbol base name -> rule id. Names are matched case-insensitively
# with trailing 'a'/'w'/'ex' variants normalized off.
_IMPORT_RULES: dict[str, str] = {
    name: rule
    for rule, names in {
        "import/process-exec": (
            "system",
            "popen",
            "execve",
            "execl",
            "execlp",
            "execvp",
            "winexec",
            "shellexecute",
            "createprocess",
            "createprocessasuser",
        ),
        "import/code-injection": (
            "virtualallocex",
            "writeprocessmemory",
            "createremotethread",
            "ntcreatethread",
            "setwindowshook",
            "queueuserapc",
            "ntmapviewofsection",
            "rtlcreateuserthread",
        ),
        "import/memory-protect": (
            "virtualprotect",
            "mprotect",
            "ntprotectvirtualmemory",
        ),
        "import/dynamic-load": (
            "loadlibrary",
            "getprocaddress",
            "dlopen",
            "dlsym",
            "ldrloaddll",
        ),
        "import/network": (
            "connect",
            "winhttpopen",
            "winhttpconnect",
            "internetopen",
            "internetopenurl",
            "httpopenrequest",
            "urldownloadtofile",
            "wsastartup",
            "curl_easy_init",
        ),
        "import/anti-debug": (
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "ntqueryinformationprocess",
            "ptrace",
            "outputdebugstring",
        ),
    }.items()
    for name in names
}


def _normalize_import(name: str) -> str:
    n = name.lower().lstrip("_")
    for suf in ("exa", "exw", "ex", "a", "w"):
        if n.endswith(suf) and n[: -len(suf)] in _IMPORT_RULES:
            return n[: -len(suf)]
    return n


def scan_imports(image: Image) -> list[Finding]:
    """Flag imported APIs that grant exec, injection, loading, or network capability."""
    out: list[Finding] = []
    for f in image.funcs:
        if f.kind != "import":
            continue
        rule = _IMPORT_RULES.get(_normalize_import(f.name))
        if rule is None:
            continue
        level, desc = RULES[rule]
        out.append(Finding(rule, level, f"{desc}: {f.name}", "import"))
    return out


# --- hardening posture ------------------------------------------------------

# Standard PE DLL characteristic bits (constants are kept literal so that older
# LIEF versions without the named enums still work).
_PE_DYNAMIC_BASE = 0x0040
_PE_HIGH_ENTROPY_VA = 0x0020
_PE_NX_COMPAT = 0x0100
_PE_GUARD_CF = 0x4000
_PE_FORCE_INTEGRITY = 0x0080
_PE_NO_SEH = 0x0400

# Mach-O header.flags MH_PIE bit.
_MH_PIE = 0x200000

# Stack canary marker symbols across toolchains.
_CANARY_SYMBOLS = {
    "__stack_chk_fail",
    "___stack_chk_fail",
    "__stack_chk_guard",
    "__security_cookie",
    "__security_check_cookie",
    "@__security_check_cookie@4",
}


def _h(rule: str, *, msg: str | None = None) -> Finding:
    level, desc = RULES[rule]
    return Finding(rule, level, msg or desc, "hardening")


def scan_hardening(image: Image) -> list[Finding]:
    """Report missing executable hardening across PE / ELF / Mach-O.

    Reads the format-specific protection flags LIEF already parses: ASLR / DEP /
    CFG on PE, PIE / NX / RELRO / BIND_NOW on ELF, MH_PIE on Mach-O. Stack-canary
    detection is symbol-based across all three. A clean image yields no findings;
    every finding is a missing protection, so silence is good news.
    """
    b = image._lief
    if b is None:
        return []
    fmt = image.fmt.upper()
    if "PE" in fmt:
        return _hardening_pe(image, b)
    if "ELF" in fmt:
        return _hardening_elf(image, b)
    if "MACHO" in fmt:
        return _hardening_macho(image, b)
    return []


def _hardening_pe(image: Image, b) -> list[Finding]:
    out: list[Finding] = []
    try:
        dll = int(b.optional_header.dll_characteristics)
    except Exception:
        dll = 0

    if not dll & _PE_DYNAMIC_BASE:
        out.append(_h("harden/no-aslr"))
    if not dll & _PE_NX_COMPAT:
        out.append(_h("harden/no-dep"))
    if not dll & _PE_GUARD_CF:
        out.append(_h("harden/no-cfg"))
    if image.arch.bits == 64 and not dll & _PE_HIGH_ENTROPY_VA:
        out.append(_h("harden/no-high-entropy-va"))

    # SafeSEH only applies to 32-bit images that use SEH.
    if image.arch.bits == 32 and not dll & _PE_NO_SEH:
        try:
            lc = b.load_configuration
            se_count = int(getattr(lc, "se_handler_count", 0) or 0)
            if se_count == 0:
                out.append(_h("harden/no-safeseh"))
        except Exception:
            out.append(_h("harden/no-safeseh"))

    if not _has_stack_canary(image):
        out.append(_h("harden/no-stack-canary"))

    if not _pe_is_signed(b):
        out.append(_h("harden/unsigned"))

    return out


def _hardening_elf(image: Image, b) -> list[Finding]:
    out: list[Finding] = []

    if not _elf_is_pie(b):
        out.append(_h("harden/no-pie"))
    if _elf_stack_is_executable(b):
        out.append(_h("harden/no-dep"))

    relro = _elf_relro_level(b)
    if relro == "none":
        out.append(_h("harden/no-relro"))
    elif relro == "partial":
        out.append(_h("harden/partial-relro"))

    if not _has_stack_canary(image):
        out.append(_h("harden/no-stack-canary"))
    if not _elf_has_fortify(image):
        out.append(_h("harden/no-fortify"))

    if image.arch.bits == 64 and image.arch.value == "arm64":
        if not _elf_has_bti_or_pac(b):
            out.append(_h("harden/no-bti-pac"))

    return out


def _hardening_macho(image: Image, b) -> list[Finding]:
    out: list[Finding] = []

    if not _macho_is_pie(b):
        out.append(_h("harden/no-pie"))
    if not _has_stack_canary(image):
        out.append(_h("harden/no-stack-canary"))
    if not _macho_is_signed(b):
        out.append(_h("harden/unsigned"))

    return out


def _lib_finding(h) -> Finding:
    rule = "lib/detected"
    level, desc = RULES[rule]
    label = f"{h.name} {h.version}" if h.version else h.name
    return Finding(
        rule, level, f"{desc}: {label}", "fingerprint", h.offset, len(h.snippet)
    )


def _has_stack_canary(image: Image) -> bool:
    for f in image.funcs:
        if f.name in _CANARY_SYMBOLS:
            return True
        bare = f.name.lstrip("@_")
        if bare in _CANARY_SYMBOLS or ("_" + bare) in _CANARY_SYMBOLS:
            return True
    return False


def _pe_is_signed(b) -> bool:
    try:
        sigs = getattr(b, "signatures", None) or []
        if len(sigs) > 0:
            return True
    except Exception:
        pass
    try:
        if getattr(b, "has_signatures", False):
            return True
    except Exception:
        pass
    return False


def _elf_is_pie(b) -> bool:
    try:
        if bool(getattr(b, "is_pie", False)):
            return True
    except Exception:
        pass
    try:
        # ET_DYN with DF_1_PIE set
        ftype = str(b.header.file_type)
        if "DYN" not in ftype.upper():
            return False
        for e in b.dynamic_entries:
            if "FLAGS_1" in str(getattr(e, "tag", "")).upper():
                # DF_1_PIE = 0x08000000
                if int(getattr(e, "value", 0)) & 0x08000000:
                    return True
        return False
    except Exception:
        return False


def _elf_stack_is_executable(b) -> bool:
    try:
        for seg in b.segments:
            if "GNU_STACK" not in str(getattr(seg, "type", "")).upper():
                continue
            flags = int(getattr(seg, "flags", 0))
            # PF_X = 1
            return bool(flags & 0x1)
    except Exception:
        pass
    return False


def _elf_relro_level(b) -> str:
    has_relro = False
    try:
        for seg in b.segments:
            if "GNU_RELRO" in str(getattr(seg, "type", "")).upper():
                has_relro = True
                break
    except Exception:
        pass
    if not has_relro:
        return "none"
    try:
        for e in b.dynamic_entries:
            tag = str(getattr(e, "tag", "")).upper()
            if "BIND_NOW" in tag:
                return "full"
            if "FLAGS_1" in tag and int(getattr(e, "value", 0)) & 0x00000001:
                # DF_1_NOW
                return "full"
            if tag.endswith(".FLAGS") and int(getattr(e, "value", 0)) & 0x08:
                # DF_BIND_NOW
                return "full"
    except Exception:
        pass
    return "partial"


def _elf_has_fortify(image: Image) -> bool:
    for f in image.funcs:
        if f.name.endswith("_chk") and f.name.startswith("__"):
            return True
    return False


def _elf_has_bti_or_pac(b) -> bool:
    # GNU property note bits AARCH64_FEATURE_1_BTI / AARCH64_FEATURE_1_PAC.
    try:
        for note in getattr(b, "notes", []) or []:
            if "PROPERTY" not in str(getattr(note, "type", "")).upper():
                continue
            desc = bytes(getattr(note, "description", b"") or b"")
            # Coarse: a property note carrying any bit signals the toolchain
            # opted into the GNU property scheme, which is the prerequisite.
            if desc:
                return True
    except Exception:
        pass
    return False


def _macho_is_pie(b) -> bool:
    try:
        flags = int(getattr(b.header, "flags", 0) or 0)
        if flags & _MH_PIE:
            return True
    except Exception:
        pass
    try:
        for f in getattr(b.header, "flags_list", []) or []:
            if "PIE" in str(f).upper():
                return True
    except Exception:
        pass
    return False


def _macho_is_signed(b) -> bool:
    try:
        if getattr(b, "has_code_signature", False):
            return True
    except Exception:
        pass
    try:
        cs = getattr(b, "code_signature", None)
        if cs is not None:
            return True
    except Exception:
        pass
    return False


# --- baseline diff ----------------------------------------------------------


def _name_set(image: Image, kind: str | None) -> set[str]:
    return {f.name for f in image.funcs if kind is None or f.kind == kind}


def diff_baseline(image: Image, baseline: Image) -> list[Finding]:
    """Report functions and imports that differ from a baseline build."""
    out: list[Finding] = []
    cur_imp, base_imp = _name_set(image, "import"), _name_set(baseline, "import")
    for name in sorted(cur_imp - base_imp):
        level, desc = RULES["diff/added-import"]
        out.append(Finding("diff/added-import", level, f"{desc}: {name}", "diff"))

    cur_fn = _name_set(image, None) - cur_imp
    base_fn = _name_set(baseline, None) - base_imp
    for rule, names in (
        ("diff/added-function", cur_fn - base_fn),
        ("diff/removed-function", base_fn - cur_fn),
    ):
        level, desc = RULES[rule]
        for name in sorted(names):
            out.append(Finding(rule, level, f"{desc}: {name}", "diff"))
    return out


# --- orchestration ----------------------------------------------------------


def _off_to_va(image: Image, off: int) -> int | None:
    for s in image.sections:
        if s.raw_size and s.raw_off <= off < s.raw_off + s.raw_size:
            return s.va + (off - s.raw_off)
    return None


def scan_image(
    image: Image,
    *,
    baseline: Image | None = None,
    entropy: bool = False,
    hardening: bool = True,
    fingerprint: bool = True,
    cve: bool = False,
) -> list[Finding]:
    """Run every check over a loaded image and return the merged findings.

    `hardening` and `fingerprint` default on (high signal, low noise). `cve`
    defaults off because it issues network requests to osv.dev; enabling it
    after a fingerprint pass surfaces known vulnerabilities against detected
    library versions.
    """
    with open(image.path, "rb") as fh:
        data = fh.read()
    findings = scan_secrets(image, data, entropy=entropy) + scan_imports(image)
    if hardening:
        findings += scan_hardening(image)
    lib_hits: list = []
    if fingerprint or cve:
        from .re.fingerprint import scan_fingerprint

        lib_hits = scan_fingerprint(image, data)
        if fingerprint:
            findings += [_lib_finding(h) for h in lib_hits]
    if cve and lib_hits:
        from .cve import scan_cve

        findings += scan_cve(lib_hits)
    if baseline is not None:
        findings += diff_baseline(image, baseline)
    findings.sort(key=lambda f: (-_LEVEL_RANK[f.level], f.rule, f.off or 0))
    return findings


def scan_file(
    path: str,
    *,
    baseline: str | None = None,
    arch: Arch | None = None,
    fmt: str | None = None,
    entropy: bool = False,
    hardening: bool = True,
    fingerprint: bool = True,
    cve: bool = False,
) -> list[Finding]:
    img = load_image(path, fmt=fmt, arch=arch)
    base = load_image(baseline, fmt=fmt, arch=arch) if baseline else None
    return scan_image(
        img,
        baseline=base,
        entropy=entropy,
        hardening=hardening,
        fingerprint=fingerprint,
        cve=cve,
    )


_BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".o", ".obj", ".bin", ".elf", ".sys"}


def iter_targets(path: str) -> list[str]:
    """Expand a file or directory into the list of files to scan."""
    if os.path.isfile(path):
        return [path]
    out: list[str] = []
    for root, _dirs, files in os.walk(path):
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext in _BINARY_EXT or ext == "":
                out.append(os.path.join(root, name))
    return sorted(out)


# --- output -----------------------------------------------------------------


def to_text(results: list[tuple[str, list[Finding]]]) -> str:
    """Human-readable report; one section per scanned file."""
    lines: list[str] = []
    total = 0
    for path, findings in results:
        lines.append(f"{path}: {len(findings)} finding(s)")
        for f in findings:
            lines.append(f"  [{f.level:<7}] {f.where:<14} {f.rule}  {f.message}")
        total += len(findings)
    lines.append(f"\n{total} finding(s) across {len(results)} file(s)")
    return "\n".join(lines)


def to_sarif(results: list[tuple[str, list[Finding]]], *, version: str = "0") -> dict:
    """Render findings as a SARIF 2.1.0 document for code-scanning ingestion."""
    seen = {f.rule for _p, fs in results for f in fs}
    rules = [
        {
            "id": rid,
            "name": rid.replace("/", "-"),
            "shortDescription": {"text": RULES[rid][1]},
            "defaultConfiguration": {"level": RULES[rid][0]},
        }
        for rid in sorted(seen)
    ]
    sarif_results = []
    for path, findings in results:
        uri = path.replace("\\", "/")
        for f in findings:
            region = (
                {} if f.off is None else {"byteOffset": f.off, "byteLength": f.length}
            )
            phys: dict = {"artifactLocation": {"uri": uri}}
            if region:
                phys["region"] = region
            sarif_results.append(
                {
                    "ruleId": f.rule,
                    "level": f.level,
                    "message": {"text": f.message},
                    "locations": [{"physicalLocation": phys}],
                }
            )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "deglyph",
                        "informationUri": "https://github.com/deglyph-re/cli",
                        "version": version,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def worst_level(results: list[tuple[str, list[Finding]]]) -> str | None:
    """The highest severity present across all findings, or None if clean."""
    levels = [f.level for _p, fs in results for f in fs]
    if not levels:
        return None
    return max(levels, key=lambda lv: _LEVEL_RANK[lv])
