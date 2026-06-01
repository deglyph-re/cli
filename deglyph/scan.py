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

Public: Finding, scan_image, scan_file, iter_targets, to_sarif, to_text, to_json,
fingerprint_of, load_ignore_file, RULES.
"""

from __future__ import annotations

import hashlib
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
    "secret/github-pat": ("error", "GitHub fine-grained personal access token"),
    "secret/gitlab-pat": ("error", "GitLab personal access token"),
    "secret/slack-token": ("error", "Slack token"),
    "secret/slack-webhook": ("warning", "Slack incoming webhook URL"),
    "secret/google-api-key": ("error", "Google API key"),
    "secret/stripe-key": ("error", "Stripe secret key"),
    "secret/npm-token": ("error", "npm access token"),
    "secret/sendgrid-key": ("error", "SendGrid API key"),
    "secret/openai-key": ("error", "OpenAI API key"),
    "secret/telegram-token": ("warning", "Telegram bot token"),
    "secret/jwt": ("warning", "JSON Web Token"),
    "secret/credential-keyword": ("warning", "Credential with an embedded value"),
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
    "diff/modified-function": ("note", "Function changed since the baseline build"),
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
    "lib/function": ("note", "Function identified by signature against the corpus"),
    "cve/known": ("error", "Known CVE against a detected library version"),
    "cve/not-checked": ("note", "CVE database not checked (offline or unreachable)"),
}

_LEVEL_RANK = {"note": 0, "warning": 1, "error": 2}

# Finding category, by rule-id prefix. Three buckets the report groups by:
#   fact       a verifiable property of the container (a hardening flag that is
#              present or absent, a fingerprinted library); not a judgment.
#   heuristic  a pattern match that suggests but does not prove (a credential-
#              shaped string, an imported capability); confirm before acting.
#   policy     a gate / drift signal (diff vs a baseline, a known CVE); whether
#              it matters is the consumer's policy call.
_CATEGORY: dict[str, str] = {
    "harden/": "fact",
    "lib/": "fact",
    "secret/": "heuristic",
    "import/": "heuristic",
    "diff/": "policy",
    "cve/": "policy",
}


def _category(rule: str) -> str:
    """The fact / heuristic / policy bucket for a rule id (by its prefix)."""
    for prefix, cat in _CATEGORY.items():
        if rule.startswith(prefix):
            return cat
    return "heuristic"


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
    # fact | heuristic | policy; defaults from the rule prefix in __post_init__
    category: str = ""

    def __post_init__(self) -> None:
        if not self.category:
            self.category = _category(self.rule)


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

# High-precision provider token formats. Each prefix/shape is specific enough
# to fire on a real credential, not on incidental strings; the generic
# credential rule below handles labeled secrets via a value check.
_SECRET_RES: list[tuple[str, re.Pattern]] = [
    ("secret/private-key", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("secret/aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("secret/github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("secret/github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("secret/gitlab-pat", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b")),
    ("secret/slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "secret/slack-webhook",
        re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+"),
    ),
    ("secret/google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("secret/stripe-key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{24,}\b")),
    ("secret/npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    (
        "secret/sendgrid-key",
        re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ),
    ("secret/openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("secret/telegram-token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_\-]{32,}\b")),
    (
        "secret/jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"
        ),
    ),
]

# Credential keyword fragment shared by the assignment and embedded-token forms.
_CRED_WORD = (
    r"api[_-]?key|secret(?:[_-]?key)?|passw(?:or)?d"
    r"|access[_-]?key|client[_-]?secret|auth[_-]?token"
)
_CRED_WORD_RE = re.compile(r"(?i)(?<![a-z])(?:" + _CRED_WORD + r")(?![a-z])")
_CRED_ASSIGN_RE = re.compile(
    r"(?i)(?<![a-z])(?:" + _CRED_WORD + r")(?![a-z])"
    r"[\"']?\s*[:=]\s*[\"']?"
    r"(?P<val>[^\s\"',;]{6,})"
)
# Characters that mark a value as a placeholder / template, not a real secret.
_PLACEHOLDER_CHARS = frozenset("%{}$<>")


def scan_secrets(image: Image, data: bytes, *, entropy: bool = False) -> list[Finding]:
    """Find embedded credentials in the binary's string table.

    Provider regexes and the credential rule are always on. The credential rule
    requires an actual value (assigned or embedded in a value-shaped token), so
    a bare keyword (a struct field, an env-var name, a scheme word) is not a
    finding. The entropy catch-all is opt-in: on native binaries it fires on
    build paths and mangled symbol names, so it is off by default.
    """
    out: list[Finding] = []
    for off, _enc, text in string_runs(data, min_len=6):
        matched = False
        for rule, rx in _SECRET_RES:
            if rx.search(text):
                out.append(_secret_finding(image, rule, off, text))
                matched = True
                break
        if not matched and _credential_evidence(text):
            out.append(_secret_finding(image, "secret/credential-keyword", off, text))
            matched = True
        if matched or not entropy:
            continue
        # Entropy catch-all over opaque, blob-like tokens (no path/symbol noise).
        for tok in text.split():
            if _looks_high_entropy(tok):
                out.append(_secret_finding(image, "secret/high-entropy", off, tok))
                break
    return out


def _alnum_classes(v: str) -> int:
    # Count upper / lower / digit only; punctuation does not make a value secret.
    return sum(
        (
            any(c.isupper() for c in v),
            any(c.islower() for c in v),
            any(c.isdigit() for c in v),
        )
    )


def _looks_like_secret_value(v: str, *, min_classes: int) -> bool:
    # A real secret value is long, mixes character cases / digits, and is not a
    # path or a format template. Counting only alnum classes keeps SCREAMING_CASE
    # constants, dictionary words with stray punctuation, and mangled symbols out.
    if len(v) < 8 or len(set(v)) <= 2:
        return False
    if any(c in _PLACEHOLDER_CHARS for c in v) or any(c in v for c in "/\\"):
        return False
    return _alnum_classes(v) >= min_classes


def _credential_evidence(text: str) -> bool:
    """True when `text` carries a credential value, not just a keyword.

    Two shapes count: a credential keyword assigned a non-trivial value
    (`password=hunter2hunter2`), or a keyword embedded in a single value-shaped
    token (`S3cr3t-demo-API-key-do-not-ship`). A bare keyword word (a struct
    field, an env-var name, a scheme like `Bearer `) is not enough.
    """
    m = _CRED_ASSIGN_RE.search(text)
    if m and _looks_like_secret_value(m.group("val"), min_classes=2):
        return True
    for tok in text.split():
        if _CRED_WORD_RE.search(tok) and _looks_like_secret_value(tok, min_classes=3):
            return True
    return False


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


# Why each import capability matters, and where it is routinely benign, so the
# finding reads as context rather than an accusation. An import is a capability,
# never proof of misuse.
_IMPORT_RATIONALE: dict[str, str] = {
    "import/process-exec": (
        "spawns processes / shells; benign in launchers, build tools, terminals"
    ),
    "import/code-injection": (
        "writes/executes code in another process; benign in debuggers, "
        "profilers, hot-patchers, anti-cheat"
    ),
    "import/memory-protect": (
        "changes page protections; benign in JITs, GC runtimes, plugin loaders"
    ),
    "import/dynamic-load": (
        "loads code at runtime; benign in plugin hosts and most large apps"
    ),
    "import/network": (
        "opens network connections; benign in any networked app or updater"
    ),
    "import/anti-debug": (
        "detects a debugger; benign in DRM and crash handlers, common in malware"
    ),
}


def scan_imports(image: Image) -> list[Finding]:
    """Flag imported APIs that grant exec, injection, loading, or network capability.

    An import is a *capability*, not a misuse: the message carries why it matters
    and where it is routinely benign (`_IMPORT_RATIONALE`) so a reviewer triages
    rather than reacts.
    """
    out: list[Finding] = []
    for f in image.funcs:
        if f.kind != "import":
            continue
        rule = _IMPORT_RULES.get(_normalize_import(f.name))
        if rule is None:
            continue
        level, desc = RULES[rule]
        rationale = _IMPORT_RATIONALE.get(rule, "")
        msg = f"{desc}: {f.name}"
        if rationale:
            msg = f"{msg} ({rationale})"
        out.append(Finding(rule, level, msg, "import"))
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


def _h(rule: str, *, msg: str | None = None, evidence: str | None = None) -> Finding:
    """A hardening finding, with optional decoded evidence from the container.

    `evidence` is the concrete flag / segment fact behind the verdict (e.g.
    `DllCharacteristics=0x8160 lacks DYNAMIC_BASE`), appended so the reader sees
    why the protection is reported missing rather than trust the label alone.
    """
    level, desc = RULES[rule]
    text = msg or desc
    if evidence:
        text = f"{text} ({evidence})"
    return Finding(rule, level, text, "hardening")


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

    dllc = f"DllCharacteristics={dll:#06x}"
    if not dll & _PE_DYNAMIC_BASE:
        out.append(_h("harden/no-aslr", evidence=f"{dllc} lacks DYNAMIC_BASE (0x40)"))
    if not dll & _PE_NX_COMPAT:
        out.append(_h("harden/no-dep", evidence=f"{dllc} lacks NX_COMPAT (0x100)"))
    if not dll & _PE_GUARD_CF:
        out.append(_h("harden/no-cfg", evidence=f"{dllc} lacks GUARD_CF (0x4000)"))
    if image.arch.bits == 64 and not dll & _PE_HIGH_ENTROPY_VA:
        out.append(
            _h(
                "harden/no-high-entropy-va",
                evidence=f"{dllc} lacks HIGH_ENTROPY_VA (0x20)",
            )
        )

    # SafeSEH only applies to 32-bit images that use SEH.
    if image.arch.bits == 32 and not dll & _PE_NO_SEH:
        try:
            lc = b.load_configuration
            se_count = int(getattr(lc, "se_handler_count", 0) or 0)
            if se_count == 0:
                out.append(_h("harden/no-safeseh"))
        except Exception:
            out.append(_h("harden/no-safeseh"))

    # A stripped release PE carries no canary symbol; the load configuration's
    # security cookie is the authoritative /GS signal.
    if not _has_stack_canary(image) and not _pe_has_security_cookie(b):
        out.append(
            _h(
                "harden/no-stack-canary",
                evidence="no __security_cookie / canary symbol",
            )
        )

    if not _pe_is_signed(b):
        out.append(_h("harden/unsigned", evidence="no Authenticode certificate table"))

    return out


def _hardening_elf(image: Image, b) -> list[Finding]:
    out: list[Finding] = []

    if not _elf_is_pie(b):
        out.append(_h("harden/no-pie", evidence="e_type is ET_EXEC, not ET_DYN"))
    if _elf_stack_is_executable(b):
        out.append(_h("harden/no-dep", evidence="PT_GNU_STACK segment is executable"))

    relro = _elf_relro_level(b)
    if relro == "none":
        out.append(_h("harden/no-relro", evidence="no PT_GNU_RELRO segment"))
    elif relro == "partial":
        out.append(
            _h("harden/partial-relro", evidence="PT_GNU_RELRO present but no BIND_NOW")
        )

    if not _has_stack_canary(image):
        out.append(_h("harden/no-stack-canary", evidence="no __stack_chk_fail symbol"))
    if not _elf_has_fortify(image):
        out.append(_h("harden/no-fortify", evidence="no *_chk fortified-libc symbols"))

    if image.arch.bits == 64 and image.arch.value == "arm64":
        if not _elf_has_bti_or_pac(b):
            out.append(
                _h("harden/no-bti-pac", evidence="no GNU_PROPERTY_AARCH64 BTI/PAC note")
            )

    return out


def _hardening_macho(image: Image, b) -> list[Finding]:
    out: list[Finding] = []

    if not _macho_is_pie(b):
        out.append(_h("harden/no-pie", evidence="MH_PIE not set in mach_header.flags"))
    if not _has_stack_canary(image):
        out.append(_h("harden/no-stack-canary", evidence="no ___stack_chk_fail symbol"))
    if not _macho_is_signed(b):
        out.append(_h("harden/unsigned", evidence="no LC_CODE_SIGNATURE load command"))

    return out


def _lib_finding(h) -> Finding:
    rule = "lib/detected"
    level, desc = RULES[rule]
    label = f"{h.name} {h.version}" if h.version else h.name
    msg = f"{desc}: {label} [{h.confidence}]"
    if h.evidence:
        msg = f"{msg} ({h.evidence})"
    return Finding(rule, level, msg, "fingerprint", h.offset, len(h.snippet))


def _funcid_finding(m) -> Finding:
    """A `lib/function` finding for a corpus-identified function (a fact).

    The message names the recovered function, the library function it matches,
    and the confidence so the reader can weigh an exact hit against a fuzzy one.
    """
    rule = "lib/function"
    level, _desc = RULES[rule]
    label = f"{m.lib} {m.version}" if m.version else m.lib
    msg = f"{m.current_name} is {m.func} ({label}) [{m.confidence}]"
    return Finding(rule, level, msg, f"{m.va:#x}")


def _has_stack_canary(image: Image) -> bool:
    for f in image.funcs:
        if f.name in _CANARY_SYMBOLS:
            return True
        bare = f.name.lstrip("@_")
        if bare in _CANARY_SYMBOLS or ("_" + bare) in _CANARY_SYMBOLS:
            return True
    return False


def _pe_has_security_cookie(b) -> bool:
    # /GS writes a non-zero VA into the load config's security_cookie field;
    # it survives symbol stripping, unlike the __security_cookie symbol.
    try:
        lc = b.load_configuration
        return int(getattr(lc, "security_cookie", 0) or 0) != 0
    except Exception:
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


def _func_identity(image: Image, va: int) -> str:
    """A relocation-stable identity for the function at `va` (for diffing).

    A real symbol name is used as-is; a recovered `sub_<va>` name churns across
    builds (the VA moves), so instead hash the function's normalized instruction
    stream via the shared content-identity engine (`re/funcsig`). The signature
    drops addresses, immediates, and register names, so a function that only
    moved keeps its identity while a changed body does not. Falls back to the
    name if disassembly yields nothing.
    """
    from .re.funcsig import func_sig

    sig = func_sig(image, va)
    return ("shape:" + sig.exact[:16]) if sig else ""


# FuncDelta kind -> the diff rule id it maps to (an unchanged function is dropped).
_DELTA_RULE = {
    "added": "diff/added-function",
    "removed": "diff/removed-function",
    "modified": "diff/modified-function",
}


def diff_baseline(image: Image, baseline: Image) -> list[Finding]:
    """Report functions and imports that differ from a baseline build.

    Imports diff by name (they are always named). Functions diff by content via
    `re/bindiff`: an exact-hash pass pairs unchanged functions, a fuzzy pass pairs
    recompiled ones (reported as `diff/modified-function` with a similarity), and
    the rest are added / removed. A function that merely moved between builds is
    not reported as removed + added.
    """
    from .re.bindiff import diff_functions

    out: list[Finding] = []
    cur_imp, base_imp = _name_set(image, "import"), _name_set(baseline, "import")
    for name in sorted(cur_imp - base_imp):
        level, desc = RULES["diff/added-import"]
        out.append(Finding("diff/added-import", level, f"{desc}: {name}", "diff"))

    deltas = diff_functions(image, baseline)
    for d in sorted(deltas, key=lambda d: (d.kind, d.name)):
        rule = _DELTA_RULE.get(d.kind)
        if rule is None:
            continue
        level, desc = RULES[rule]
        msg = f"{desc}: {d.name}"
        if d.kind == "modified":
            msg = f"{msg} ({d.similarity:.0%} similar)"
        out.append(Finding(rule, level, msg, "diff"))
    return out


# --- orchestration ----------------------------------------------------------


def _is_ignored(rule: str, ignore: set[str]) -> bool:
    # Exact rule id, or a category prefix when the token ends in '/'
    # (e.g. 'secret/' suppresses every secret/* rule).
    if rule in ignore:
        return True
    return any(tok.endswith("/") and rule.startswith(tok) for tok in ignore)


def fingerprint_of(f: Finding) -> str:
    """Stable content hash of a finding, for per-finding suppression.

    Keyed on rule + message (the message carries the offending string / symbol),
    not the offset, so the same finding in a moved binary keeps its fingerprint.
    """
    digest = hashlib.sha1(f"{f.rule}|{f.message}".encode("utf-8", "replace"))
    return digest.hexdigest()[:12]


def load_rule_config(path: str) -> dict[str, str]:
    """Parse a `.deglyphrules` JSON file into a rule-id -> level override map.

    Format: `{"rules": {"harden/no-cfg": {"level": "off"}, "secret/jwt":
    {"level": "error"}}}`. A level of `off` suppresses the rule; any of
    note/warning/error retunes it (so a consumer can promote or demote a rule's
    severity for their gate without editing the tool). A missing or malformed
    file yields an empty map, so the scan still runs with defaults.
    """
    out: dict[str, str] = {}
    try:
        import json

        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        rules = doc.get("rules", {}) if isinstance(doc, dict) else {}
        for rule, spec in rules.items():
            level = spec.get("level") if isinstance(spec, dict) else None
            if level in ("off", "note", "warning", "error"):
                out[rule] = level
    except (OSError, ValueError, AttributeError):
        pass
    return out


def _apply_rule_config(
    findings: list[Finding], config: dict[str, str]
) -> list[Finding]:
    """Drop `off` rules and retune levels per a rule-config map."""
    if not config:
        return findings
    out: list[Finding] = []
    for f in findings:
        level = config.get(f.rule)
        if level == "off":
            continue
        if level in ("note", "warning", "error"):
            f.level = level
        out.append(f)
    return out


def load_ignore_file(path: str) -> tuple[set[str], set[str]]:
    """Parse a `.deglyphignore` into (rule tokens, fingerprints).

    One token per line; `#` starts a comment. A `fingerprint:` / `fp:` prefix
    suppresses a single finding by its hash; any other token is a rule id or a
    category prefix, matched exactly as `--ignore` does. A missing or unreadable
    file yields empty sets, so discovery is best-effort.
    """
    rules: set[str] = set()
    fps: set[str] = set()
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                low = line.lower()
                if low.startswith(("fingerprint:", "fp:")):
                    fps.add(line.split(":", 1)[1].strip())
                else:
                    rules.add(line)
    except (OSError, ValueError):
        # ValueError covers a UnicodeDecodeError on invalid UTF-8 bytes; a
        # corrupt ignore file must not abort the whole scan (matches
        # load_rule_config, and the docstring's "unreadable file yields empty").
        pass
    return rules, fps


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
    offline: bool = False,
    lib_signatures: str | None = None,
    identify: bool = False,
    func_signatures: str | None = None,
    ignore: set[str] | None = None,
    ignore_fp: set[str] | None = None,
    rule_config: dict[str, str] | None = None,
) -> list[Finding]:
    """Run every check over a loaded image and return the merged findings.

    `hardening` and `fingerprint` default on (high signal, low noise). `cve`
    defaults off because it issues network requests to osv.dev; enabling it
    after a fingerprint pass surfaces known vulnerabilities against detected
    library versions. `identify` is opt-in: it runs function discovery and
    matches each function against the signature corpus (`re/funcdb`), which is
    slower. `ignore` drops findings by rule (exact id, or a category prefix
    ending in '/') and `ignore_fp` by per-finding fingerprint, so the report and
    the exit code agree.
    """
    with open(image.path, "rb") as fh:
        data = fh.read()
    findings = scan_secrets(image, data, entropy=entropy) + scan_imports(image)
    if hardening:
        findings += scan_hardening(image)
    lib_hits: list = []
    if fingerprint or cve:
        from .re.fingerprint import load_signatures, scan_fingerprint

        sigs = load_signatures(lib_signatures) if lib_signatures else None
        lib_hits = scan_fingerprint(image, data, signatures=sigs)
        if fingerprint:
            findings += [_lib_finding(h) for h in lib_hits]
    if cve and lib_hits:
        from .cve import scan_cve

        findings += scan_cve(lib_hits, offline=offline)
    if identify:
        from .re.discover import discover_functions
        from .re.funcdb import identify_functions, load_func_db

        discover_functions(image)
        db = load_func_db(func_signatures)
        findings += [_funcid_finding(m) for m in identify_functions(image, db)]
    if baseline is not None:
        findings += diff_baseline(image, baseline)
    findings = _apply_rule_config(findings, rule_config or {})
    if ignore:
        findings = [f for f in findings if not _is_ignored(f.rule, ignore)]
    if ignore_fp:
        findings = [f for f in findings if fingerprint_of(f) not in ignore_fp]
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
    offline: bool = False,
    lib_signatures: str | None = None,
    identify: bool = False,
    func_signatures: str | None = None,
    ignore: set[str] | None = None,
    ignore_fp: set[str] | None = None,
    rule_config: dict[str, str] | None = None,
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
        offline=offline,
        lib_signatures=lib_signatures,
        identify=identify,
        func_signatures=func_signatures,
        ignore=ignore,
        ignore_fp=ignore_fp,
        rule_config=rule_config,
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


# Report order and headings for the three finding categories. Public so the
# report renderers (report.py) group findings the same way.
CATEGORY_ORDER = ("fact", "heuristic", "policy")
CATEGORY_LABEL = {
    "fact": "Facts (verifiable container properties)",
    "heuristic": "Heuristics (patterns to confirm, not proof)",
    "policy": "Policy (drift / known-CVE gates)",
}


def to_text(results: list[tuple[str, list[Finding]]]) -> str:
    """Human-readable report; one section per file, grouped fact/heuristic/policy."""
    lines: list[str] = []
    total = 0
    for path, findings in results:
        lines.append(f"{path}: {len(findings)} finding(s)")
        for cat in CATEGORY_ORDER:
            group = [f for f in findings if f.category == cat]
            if not group:
                continue
            lines.append(f"  {CATEGORY_LABEL[cat]}:")
            for f in group:
                lines.append(f"    [{f.level:<7}] {f.where:<14} {f.rule}  {f.message}")
        total += len(findings)
    lines.append(f"\n{total} finding(s) across {len(results)} file(s)")
    return "\n".join(lines)


def to_json(results: list[tuple[str, list[Finding]]], *, version: str = "0") -> dict:
    """Machine-readable findings for jq / custom gates / other tooling.

    Each finding carries its `fingerprint` (the value a `.deglyphignore`
    `fingerprint:` line suppresses); `summary` totals by level for a quick gate.
    """
    levels = [f.level for _p, fs in results for f in fs]
    counts = Counter(levels)
    files = [
        {
            "path": path.replace("\\", "/"),
            "findings": [
                {
                    "rule": f.rule,
                    "level": f.level,
                    "category": f.category,
                    "message": f.message,
                    "where": f.where,
                    "offset": f.off,
                    "length": f.length,
                    "fingerprint": fingerprint_of(f),
                }
                for f in findings
            ],
        }
        for path, findings in results
    ]
    return {
        "tool": "deglyph",
        "version": version,
        "summary": {
            "files": len(results),
            "findings": len(levels),
            "error": counts.get("error", 0),
            "warning": counts.get("warning", 0),
            "note": counts.get("note", 0),
        },
        "files": files,
    }


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
                    "properties": {"category": f.category},
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


# shields.io color per worst level; a clean scan is green.
_BADGE_COLOR = {"error": "red", "warning": "yellow", "note": "blue"}


def to_badge(
    results: list[tuple[str, list[Finding]]], *, label: str = "deglyph"
) -> dict:
    """A shields.io endpoint object summarizing a scan, for a per-run CI badge.

    Publish the JSON somewhere with a stable raw URL (a committed file, a gist,
    a gh-pages artifact) and render it with an endpoint badge:
    `https://img.shields.io/endpoint?url=<raw url>`.
    """
    counts = Counter(f.level for _p, fs in results for f in fs)
    worst = worst_level(results)
    if worst is None:
        message, color = "clean", "brightgreen"
    else:
        # Worst-first, nonzero levels only: "1 error, 2 warnings".
        parts = [
            f"{counts[lv]} {lv}" + ("" if counts[lv] == 1 else "s")
            for lv in ("error", "warning", "note")
            if counts.get(lv)
        ]
        message, color = ", ".join(parts), _BADGE_COLOR[worst]
    return {
        "schemaVersion": 1,
        "label": label,
        "message": message,
        "color": color,
    }
