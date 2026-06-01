# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Command-line entry point.

  deglyph <binary>                      open the interface
  deglyph <binary> --fmt PE --arch x64  override format / architecture
  deglyph <binary> --slice N            pick a fat Mach-O slice (default: host arch)
  deglyph <binary> --list               print the function table and exit
  deglyph <binary> --analyze NAME       headless constant/CRC analysis of a function
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys

from .core.image import Arch, load_image


def _setup_logging(*, verbose: bool, debug: bool) -> None:
    """Route diagnostics to stderr. Default is quiet (warnings and errors only)."""
    level = logging.DEBUG if debug else logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=level, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr
    )


def _resolve_binary(path: str) -> str:
    """Resolve a bare name to a real file: PATH, then Windows System32.

    Lets `deglyph notepad.exe` work without the full `C:/Windows/...` path. An
    existing file path is returned unchanged; an unresolved name is returned as
    given so the loader reports the original argument in its error.
    """
    if os.path.isfile(path):
        return path
    found = shutil.which(path)
    if found:
        return found
    if os.name == "nt" and os.sep not in path and "/" not in path:
        sys32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
        cand = os.path.join(sys32, path)
        if os.path.isfile(cand):
            return cand
    return path


def _arch(s: str | None) -> Arch | None:
    if not s:
        return None
    s = s.lower().replace("_", "-")
    return {
        "x86": Arch.X86,
        "x32": Arch.X86,
        "32": Arch.X86,
        "x64": Arch.X64,
        "x86-64": Arch.X64,
        "amd64": Arch.X64,
        "64": Arch.X64,
        "arm": Arch.ARM,
        "arm64": Arch.ARM64,
        "aarch64": Arch.ARM64,
    }.get(s, None)


def _build_parser() -> argparse.ArgumentParser:
    """The flag-based parser for `deglyph BINARY ...` (subcommands handled apart)."""
    ap = argparse.ArgumentParser(
        prog="deglyph",
        description="deglyph - a terminal reverse-engineering tool for native binaries.",
        epilog=(
            "subcommands (run `deglyph <cmd> -h` for details):\n"
            "  scan PATH      scan a binary/dir for hardening posture, secrets,\n"
            "                 linked libraries, CVEs, risky imports, and drift\n"
            "  sbom PATH      emit a CycloneDX or SPDX bill of materials\n"
            "  login TOKEN    store a hosted-AI token (Pro tier); logout clears it\n"
            "\nwith no binary, deglyph opens the interface on its welcome screen."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("binary", nargs="?", help="path to a PE / ELF / Mach-O object")
    ap.add_argument("--fmt", help="force container format (PE/ELF/MachO)")
    ap.add_argument("--arch", help="force architecture (x86/x64/arm/arm64)")
    ap.add_argument(
        "--slice",
        type=int,
        metavar="N",
        help="select fat (universal) Mach-O slice by index (default: host arch)",
    )
    ap.add_argument("--list", action="store_true", help="print functions and exit")
    ap.add_argument(
        "--analyze", metavar="NAME", help="headless analysis of one function"
    )
    ap.add_argument(
        "--strings",
        action="store_true",
        help="print mapped string literals (ASCII / UTF-8 / UTF-16LE) and exit",
    )
    ap.add_argument(
        "--strings-all",
        action="store_true",
        help="with --strings: include unmapped runs and section names (raw dump)",
    )
    ap.add_argument(
        "--strings-min",
        type=int,
        default=4,
        metavar="N",
        help="with --strings: minimum run length (default 4)",
    )
    ap.add_argument(
        "--strings-section",
        metavar="NAME",
        help="with --strings: only strings in this section",
    )
    ap.add_argument(
        "-v", "--verbose", action="store_true", help="info-level logging to stderr"
    )
    ap.add_argument(
        "--debug", action="store_true", help="debug-level logging to stderr"
    )
    ap.add_argument(
        "--no-discover",
        action="store_true",
        help="skip sub_* discovery of unexported functions",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="emit --list / --analyze output as JSON",
    )
    ap.add_argument(
        "--ascii",
        action="store_true",
        help="use ASCII glyphs in the interface (for limited terminals)",
    )
    ap.add_argument(
        "--nerd",
        action="store_true",
        help="use Nerd Font icons (Font Awesome glyphs; needs a Nerd Font terminal)",
    )
    ap.add_argument("--version", action="store_true")
    return ap


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:]) if argv is None else list(argv)
    if argv and argv[0] == "scan":
        return _scan_cli(argv[1:])
    if argv and argv[0] == "sbom":
        return _sbom_cli(argv[1:])
    if argv and argv[0] == "export":
        return _export_cli(argv[1:])
    if argv and argv[0] == "project":
        return _project_cli(argv[1:])
    if argv and argv[0] in ("login", "logout"):
        return _account_cli(argv[0], argv[1:])

    ap = _build_parser()
    args = ap.parse_args(argv)

    if args.ascii:
        # read by deglyph.tui.glyphs at import
        os.environ["DEGLYPH_ASCII"] = "1"
    if args.nerd:
        os.environ["DEGLYPH_NERD"] = "1"
    _setup_logging(verbose=args.verbose, debug=args.debug)

    if args.version:
        from . import __version__

        print(f"deglyph {__version__}")
        return 0

    arch = _arch(args.arch)

    # Headless modes need a target; everything else opens the interface (and with
    # no binary the interface starts on the welcome screen).
    if args.list or args.analyze or args.strings:
        if not args.binary:
            print(
                "deglyph: --list / --analyze / --strings require a binary",
                file=sys.stderr,
            )
            ap.print_help()
            return 2
        return _headless(
            _resolve_binary(args.binary),
            fmt=args.fmt,
            arch=arch,
            slice_index=args.slice,
            do_list=args.list,
            analyze=args.analyze,
            strings=args.strings,
            strings_all=args.strings_all,
            strings_min=args.strings_min,
            strings_section=args.strings_section,
            discover=not args.no_discover,
            as_json=args.json,
        )

    binary = _resolve_binary(args.binary) if args.binary else None
    from .tui import run

    # With a binary on the command line, open it directly; the welcome screen
    # is for picking one when none was named.
    run(
        binary,
        fmt=args.fmt,
        arch=arch,
        slice_index=args.slice,
        discover=not args.no_discover,
        welcome=binary is None,
    )
    return 0


def _account_cli(cmd: str, argv: list[str]) -> int:
    """`deglyph login <token>` / `deglyph logout` - hosted (Pro) tier token store."""
    from . import account

    if cmd == "login":
        ap = argparse.ArgumentParser(prog="deglyph login")
        ap.add_argument("token", help="hosted-AI token issued at deglyph.dev")
        args = ap.parse_args(argv)
        if not account.save_token(args.token):
            print("deglyph: could not store the token (see logs).")
            return 1
        print("deglyph: hosted AI token stored.")
        return 0

    argparse.ArgumentParser(prog="deglyph logout").parse_args(
        argv
        # reject extras / -h
    )
    print(
        "deglyph: logged out." if account.clear_token() else "deglyph: not logged in."
    )
    return 0


def _build_scan_parser() -> argparse.ArgumentParser:
    """The argument parser for `deglyph scan` (the subcommand dispatched in main)."""
    ap = argparse.ArgumentParser(
        prog="deglyph scan",
        description=(
            "Scan a binary (or directory) for hardening posture, secrets, linked "
            "libraries, CVEs, risky imports, and drift."
        ),
    )
    ap.add_argument("path", help="binary or directory to scan")
    ap.add_argument("--baseline", help="compare against this prior build")
    ap.add_argument("--fmt", help="force container format (PE/ELF/MachO)")
    ap.add_argument("--arch", help="force architecture (x86/x64/arm/arm64)")
    ap.add_argument(
        "--format",
        dest="fmt_out",
        choices=("text", "markdown", "html", "sarif", "json", "badge"),
        default="text",
        help="output format (default: text)",
    )
    ap.add_argument(
        "--sarif",
        action="store_true",
        help="alias for --format sarif (kept for older CI configs)",
    )
    ap.add_argument(
        "--output",
        "-o",
        help="write the report to this file (default: stdout)",
    )
    ap.add_argument(
        "--entropy",
        action="store_true",
        help="also flag high-entropy blobs (noisier; off by default)",
    )
    ap.add_argument(
        "--no-hardening",
        action="store_true",
        help="skip the cross-platform hardening posture check",
    )
    ap.add_argument(
        "--no-fingerprint",
        action="store_true",
        help="skip third-party library fingerprinting",
    )
    ap.add_argument(
        "--cve",
        action="store_true",
        help="query osv.dev for CVEs against detected libraries (network)",
    )
    ap.add_argument(
        "--offline",
        action="store_true",
        help="never touch the network; report CVEs as not-checked rather than clean",
    )
    ap.add_argument(
        "--lib-signatures",
        metavar="PATH",
        help="extra library signature database (JSON) merged with the built-ins",
    )
    ap.add_argument(
        "--ignore",
        action="append",
        metavar="RULE",
        help=(
            "suppress findings by rule id (repeatable, or comma-separated); a "
            "trailing '/' ignores a whole category, e.g. --ignore secret/"
        ),
    )
    ap.add_argument(
        "--ignore-file",
        metavar="PATH",
        help="suppression file (default: .deglyphignore in the working directory)",
    )
    ap.add_argument(
        "--rule-config",
        metavar="PATH",
        help="JSON of per-rule level overrides (default: .deglyphrules in the CWD)",
    )
    ap.add_argument(
        "--fail-on",
        choices=("note", "warning", "error", "never"),
        default="warning",
        help="minimum level that sets a non-zero exit (default: warning)",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--debug", action="store_true")
    return ap


def _collect_ignores(args, scanmod) -> tuple[set[str], set[str]]:
    """Merge `--ignore` tokens with a `.deglyphignore` into (rules, fingerprints)."""
    # --ignore is repeatable and each value may be comma-separated.
    ignore = {
        tok.strip()
        for chunk in (args.ignore or [])
        for tok in chunk.split(",")
        if tok.strip()
    }
    # Layer a .deglyphignore (explicit --ignore-file, else CWD) on top.
    ignore_fp: set[str] = set()
    ignore_path = args.ignore_file or os.path.join(os.getcwd(), ".deglyphignore")
    if args.ignore_file or os.path.isfile(ignore_path):
        file_rules, ignore_fp = scanmod.load_ignore_file(ignore_path)
        ignore |= file_rules
    return ignore, ignore_fp


def _collect_rule_config(args, scanmod) -> dict[str, str]:
    """Load the rule-config JSON (explicit --rule-config, else .deglyphrules)."""
    path = args.rule_config or os.path.join(os.getcwd(), ".deglyphrules")
    if args.rule_config or os.path.isfile(path):
        return scanmod.load_rule_config(path)
    return {}


def _scan_cli(argv: list[str]) -> int:
    """`deglyph scan` - hardening / secret / lib / import / drift scan for CI gating."""
    from . import __version__
    from . import scan as scanmod

    args = _build_scan_parser().parse_args(argv)
    _setup_logging(verbose=args.verbose, debug=args.debug)

    fmt_out = "sarif" if args.sarif else args.fmt_out
    ignore, ignore_fp = _collect_ignores(args, scanmod)
    rule_config = _collect_rule_config(args, scanmod)

    arch = _arch(args.arch)
    results: list[tuple[str, list]] = []
    for target in scanmod.iter_targets(_resolve_binary(args.path)):
        try:
            findings = scanmod.scan_file(
                target,
                baseline=args.baseline,
                arch=arch,
                fmt=args.fmt,
                entropy=args.entropy,
                hardening=not args.no_hardening,
                fingerprint=not args.no_fingerprint,
                cve=args.cve,
                offline=args.offline,
                lib_signatures=args.lib_signatures,
                ignore=ignore,
                ignore_fp=ignore_fp,
                rule_config=rule_config,
            )
        # one unreadable file should not abort the scan
        except Exception as e:
            logging.getLogger("deglyph.scan").warning("skip %s: %s", target, e)
            continue
        results.append((target, findings))

    payload = _render_scan(results, fmt_out, version=__version__)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload)
    else:
        print(payload)

    worst = scanmod.worst_level(results)
    if worst is None or args.fail_on == "never":
        return 0
    ranks = {"note": 0, "warning": 1, "error": 2}
    return 1 if ranks[worst] >= ranks[args.fail_on] else 0


def _render_scan(results, fmt_out: str, *, version: str) -> str:
    """Pick the renderer for `--format` and return the body to write out."""
    from . import scan as scanmod

    if fmt_out == "sarif":
        return json.dumps(scanmod.to_sarif(results, version=version), indent=2)
    if fmt_out == "json":
        return json.dumps(scanmod.to_json(results, version=version), indent=2)
    if fmt_out == "badge":
        return json.dumps(scanmod.to_badge(results), indent=2)
    if fmt_out == "markdown":
        from . import report

        return report.to_markdown(results)
    if fmt_out == "html":
        from . import report

        return report.to_html(results)
    return scanmod.to_text(results)


def _sbom_cli(argv: list[str]) -> int:
    """`deglyph sbom` - emit a CycloneDX or SPDX bill of materials from a binary."""
    from . import sbom as sbommod

    ap = argparse.ArgumentParser(
        prog="deglyph sbom",
        description="Emit a CycloneDX or SPDX bill of materials from a native binary.",
    )
    ap.add_argument("path", help="binary to inspect")
    ap.add_argument(
        "--format",
        dest="fmt_out",
        choices=("cyclonedx", "spdx"),
        default="cyclonedx",
        help="SBOM format (default: cyclonedx)",
    )
    ap.add_argument("--fmt", help="force container format (PE/ELF/MachO)")
    ap.add_argument("--arch", help="force architecture (x86/x64/arm/arm64)")
    ap.add_argument("--output", "-o", help="write to this file (default: stdout)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args(argv)
    _setup_logging(verbose=args.verbose, debug=args.debug)

    arch = _arch(args.arch)
    try:
        doc = sbommod.build_sbom(
            _resolve_binary(args.path),
            fmt=args.fmt_out,
            arch=arch,
            force_fmt=args.fmt,
        )
    except Exception as e:
        print(f"deglyph sbom: {e}", file=sys.stderr)
        return 1
    text = json.dumps(doc, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        print(text)
    return 0


def _export_cli(argv: list[str]) -> int:
    """`deglyph export` - a versioned JSON analysis document for other tools."""
    from . import export as exportmod

    ap = argparse.ArgumentParser(
        prog="deglyph export",
        description="Emit a versioned JSON analysis document for a native binary.",
    )
    ap.add_argument("path", help="binary to inspect")
    ap.add_argument("--fmt", help="force container format (PE/ELF/MachO)")
    ap.add_argument("--arch", help="force architecture (x86/x64/arm/arm64)")
    ap.add_argument(
        "--cfg",
        action="store_true",
        help="include per-function control-flow blocks (slower, larger)",
    )
    ap.add_argument(
        "--max-funcs",
        type=int,
        metavar="N",
        help="cap the per-function sections to the first N functions",
    )
    ap.add_argument("--output", "-o", help="write to this file (default: stdout)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args(argv)
    _setup_logging(verbose=args.verbose, debug=args.debug)

    try:
        doc = exportmod.export_file(
            _resolve_binary(args.path),
            fmt=args.fmt,
            arch=_arch(args.arch),
            include_cfg=args.cfg,
            max_funcs=args.max_funcs,
        )
    except Exception as e:
        print(f"deglyph export: {e}", file=sys.stderr)
        return 1
    text = json.dumps(doc, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        print(text)
    return 0


def _project_cli(argv: list[str]) -> int:
    """`deglyph project export|import` - move annotations between machines.

    A sidecar is keyed by the binary's absolute path, so it does not follow the
    binary to another machine. The portable file is path-independent: it carries
    only the renames, notes, bookmarks, and saved view, reattached to whatever
    binary the import targets.
    """
    from . import store

    ap = argparse.ArgumentParser(
        prog="deglyph project",
        description="Export or import a binary's annotations as a portable file.",
    )
    ap.add_argument("action", choices=("export", "import"))
    ap.add_argument("binary", help="the binary the annotations belong to")
    ap.add_argument(
        "--file",
        "-f",
        required=True,
        help="portable project file to write (export) or read (import)",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args(argv)
    _setup_logging(verbose=args.verbose, debug=args.debug)

    if args.action == "export":
        anno = store.load(args.binary)
        if anno.is_empty():
            print(
                "deglyph project: nothing to export (no annotations)", file=sys.stderr
            )
            return 1
        try:
            with open(args.file, "w", encoding="utf-8") as fh:
                json.dump(anno.to_portable(), fh, indent=2)
        except OSError as e:
            print(f"deglyph project: {e}", file=sys.stderr)
            return 1
        print(f"wrote {args.file}")
        return 0

    try:
        with open(args.file, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as e:
        print(f"deglyph project: {e}", file=sys.stderr)
        return 1
    anno = store.Annotations.from_portable(args.binary, data)
    anno.save()
    print(
        f"imported {len(anno.names)} rename(s), {len(anno.comments)} note(s), "
        f"{len(anno.bookmarks)} bookmark(s) for {os.path.basename(args.binary)}"
    )
    return 0


def _headless(
    path,
    *,
    fmt,
    arch,
    slice_index=None,
    do_list,
    analyze,
    strings=False,
    strings_all=False,
    strings_min=4,
    strings_section=None,
    discover=True,
    as_json=False,
) -> int:
    from rich.console import Console

    from .re import (
        call_immediate_args,
        detect_crc_loops,
        discover_functions,
        extract_strings,
        immediate_stores,
        thunk_chain,
    )

    c = Console()
    try:
        img = load_image(path, fmt=fmt, arch=arch, slice_index=slice_index)
    except Exception as e:
        if as_json:
            print(json.dumps({"error": f"load error: {e}"}))
        else:
            c.print(f"[red]load error:[/] {e}")
        return 1
    if discover:
        discover_functions(img)
    # The --strings-* flags must reach extract_strings; threading them this far
    # only to drop them at the call site silently ignored the user's request.
    str_kw = dict(min_len=strings_min, section=strings_section, raw=strings_all)
    if as_json:
        return _emit_json(img, do_list, analyze, strings, str_kw)
    c.print(
        f"[bold #e8a06a]{path}[/]  {img.fmt}/{img.arch.value} base={img.base:#x} "
        f"· {len(img.funcs)} functions"
    )
    if do_list:
        for f in sorted(img.funcs, key=lambda x: x.va):
            mark = " [yellow](candidate)[/]" if f.is_candidate else ""
            c.print(f"  [dim]{f.va:#012x}[/] [#6a9fb5]{f.kind:<7}[/] {f.display}{mark}")
    if strings:
        # plain print (no Rich markup) so the dump pipes / greps cleanly
        for st in extract_strings(img, **str_kw):
            print(f"{st.va:#012x}  {st.section:<8} {st.encoding:<5} {st.text}")
    if analyze:
        matches = [f for f in img.funcs if analyze.lower() in f.display.lower()]
        if not matches:
            c.print(f"[red]no function matching[/] {analyze!r}")
            return 1
        for f in matches[:10]:
            chain = thunk_chain(img, f.va)
            real = chain[-1]
            c.print(
                f"\n[bold #d97757]{f.display}[/]  chain="
                f"{' → '.join(hex(x) for x in chain)}"
            )
            for s in immediate_stores(img, real)[:16]:
                where = "abs" if s.is_absolute else f"{s.base}{_disp(s.signed_disp)}"
                conf = _conf_tag(s.evidence)
                c.print(
                    f"   store \\[{where}].{s.size} = [#7fb069]{s.value:#04x}[/]{conf}"
                )
            for a in call_immediate_args(img, real)[:12]:
                tgt = ""
                if a.target is not None:
                    # exact export/symbol only
                    tf = img.func_at(a.target)
                    tgt = f" → {tf.display}" if tf else f" → sub_{a.target:#x}"
                conf = _conf_tag(a.evidence)
                c.print(
                    f"   arg {a.reg} = [#7fb069]{a.value:#04x}[/] "
                    f"at call {a.call_addr:#x}{tgt}{conf}"
                )
            for cr in detect_crc_loops(img, real):
                c.print(
                    f"   {cr.kind} loop {cr.start:#x}: "
                    f"poly={[hex(p) for p in cr.polys]} "
                    f"init={hex(cr.init) if cr.init else None}{_conf_tag(cr.evidence)}"
                )
    return 0


def _disp(signed: int) -> str:
    """Signed-displacement suffix for a memory operand (`+0x4` / `-0x8` / '')."""
    if signed == 0:
        return ""
    return f"+{signed:#x}" if signed > 0 else f"-{-signed:#x}"


def _conf_tag(ev) -> str:
    """A short `[dim]` confidence/caveat tag for a detector hit, or '' for high."""
    if ev.confidence == "high" and not ev.caveats:
        return ""
    note = f" {ev.caveats[0]}" if ev.caveats else ""
    return f"  [dim]({ev.confidence}{note})[/]"


def _analysis_support(arch) -> dict:
    """Per-feature architecture support, surfaced in JSON so absent != unsupported.

    The operand-level detectors (immediate stores, call-arg constants, CRC loops,
    constants, data refs) run on x86/x64/ARM64 via the arch-neutral operand
    walker; pseudo-C is still an x86-only statement model. A feature marked False
    here yields an empty result by design, not because nothing was found.
    """
    ops = arch in (Arch.X86, Arch.X64, Arch.ARM64)
    return {
        "immediate_stores": ops,
        "call_immediate_args": ops,
        "detect_crc_loops": ops,
        "function_constants": ops,
        "referenced_data": arch != Arch.UNKNOWN,
        "pseudo_c": arch in (Arch.X86, Arch.X64),
    }


def _emit_json(img, do_list, analyze, strings=False, str_kw=None) -> int:
    """Machine-readable --list / --analyze / --strings output for scripting."""
    out: dict = {
        "path": img.path,
        "fmt": img.fmt,
        "arch": img.arch.value,
        "base": img.base,
        # Which analyses run for this binary's architecture, so a consumer can
        # tell "no hits" apart from "not supported on this arch".
        "analysis_support": _analysis_support(img.arch),
    }
    if do_list:
        out["functions"] = [
            {
                "va": f.va,
                "name": f.name,
                "display": f.display,
                "kind": f.kind,
                "confidence": f.confidence,
                "evidence": list(f.evidence),
            }
            for f in sorted(img.funcs, key=lambda x: x.va)
        ]
    if strings:
        from .re import extract_strings

        out["strings"] = [
            {"va": s.va, "section": s.section, "encoding": s.encoding, "text": s.text}
            for s in extract_strings(img, **(str_kw or {}))
        ]
    if analyze:
        matches = [f for f in img.funcs if analyze.lower() in f.display.lower()]
        if not matches:
            print(json.dumps({"error": f"no function matching {analyze!r}"}))
            return 1
        out["analysis"] = [_analysis_record(img, f) for f in matches[:10]]
    print(json.dumps(out, indent=2))
    return 0


def _analysis_record(img, f) -> dict:
    from .re import call_immediate_args, detect_crc_loops, immediate_stores, thunk_chain

    chain = thunk_chain(img, f.va)
    real = chain[-1]
    return {
        "name": f.display,
        "va": f.va,
        "chain": chain,
        "stores": [
            {
                "addr": s.addr,
                "base": s.base,
                "disp": s.signed_disp,
                "size": s.size,
                "value": s.value,
                "evidence": _evidence_json(s.evidence),
            }
            for s in immediate_stores(img, real)[:16]
        ],
        "call_args": [
            {
                "call_addr": a.call_addr,
                "reg": a.reg,
                "value": a.value,
                "target": a.target,
                "evidence": _evidence_json(a.evidence),
            }
            for a in call_immediate_args(img, real)[:12]
        ],
        "crc": [
            {
                "start": cr.start,
                "end": cr.end,
                "kind": cr.kind,
                "polys": cr.polys,
                "init": cr.init,
                "evidence": _evidence_json(cr.evidence),
            }
            for cr in detect_crc_loops(img, real)
        ],
    }


def _evidence_json(ev) -> dict:
    """Serialize an `Evidence` record for the machine-readable analysis output."""
    return {
        "confidence": ev.confidence,
        "reasons": list(ev.reasons),
        "caveats": list(ev.caveats),
        "support": list(ev.support),
    }


if __name__ == "__main__":
    sys.exit(main())
