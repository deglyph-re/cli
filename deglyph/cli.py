# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""
Command-line entry point.

  deglyph <binary>                      open the interface
  deglyph <binary> --fmt PE --arch x64  override format / architecture
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
    ap.add_argument("--list", action="store_true", help="print functions and exit")
    ap.add_argument(
        "--analyze", metavar="NAME", help="headless analysis of one function"
    )
    ap.add_argument(
        "--strings",
        action="store_true",
        help="print extracted strings (ASCII / UTF-16) and exit",
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
            do_list=args.list,
            analyze=args.analyze,
            strings=args.strings,
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
        account.save_token(args.token)
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
        choices=("text", "markdown", "html", "sarif", "json"),
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


def _scan_cli(argv: list[str]) -> int:
    """`deglyph scan` - hardening / secret / lib / import / drift scan for CI gating."""
    from . import __version__
    from . import scan as scanmod

    args = _build_scan_parser().parse_args(argv)
    _setup_logging(verbose=args.verbose, debug=args.debug)

    fmt_out = "sarif" if args.sarif else args.fmt_out
    ignore, ignore_fp = _collect_ignores(args, scanmod)

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
                ignore=ignore,
                ignore_fp=ignore_fp,
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


def _headless(
    path, *, fmt, arch, do_list, analyze, strings=False, discover=True, as_json=False
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
        img = load_image(path, fmt=fmt, arch=arch)
    except Exception as e:
        if as_json:
            print(json.dumps({"error": f"load error: {e}"}))
        else:
            c.print(f"[red]load error:[/] {e}")
        return 1
    if discover:
        discover_functions(img)
    if as_json:
        return _emit_json(img, do_list, analyze, strings)
    c.print(
        f"[bold #e8a06a]{path}[/]  {img.fmt}/{img.arch.value} base={img.base:#x} "
        f"· {len(img.funcs)} functions"
    )
    if do_list:
        for f in sorted(img.funcs, key=lambda x: x.va):
            c.print(f"  [dim]{f.va:#012x}[/] [#6a9fb5]{f.kind:<7}[/] {f.display}")
    if strings:
        # plain print (no Rich markup) so the dump pipes / greps cleanly
        for st in extract_strings(img):
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
                where = "abs" if s.is_absolute else s.base
                c.print(
                    f"   store \\[{where}+{s.disp & 0xff:#04x}].{s.size} = [#7fb069]{s.value:#04x}[/]"
                )
            for a in call_immediate_args(img, real)[:12]:
                tgt = ""
                if a.target is not None:
                    # exact export/symbol only
                    tf = img.func_at(a.target)
                    tgt = f" → {tf.display}" if tf else f" → sub_{a.target:#x}"
                c.print(
                    f"   arg {a.reg} = [#7fb069]{a.value:#04x}[/] at call {a.call_addr:#x}{tgt}"
                )
            for cr in detect_crc_loops(img, real):
                c.print(
                    f"   crc loop {cr.start:#x}: poly={[hex(p) for p in cr.polys]} "
                    f"init={hex(cr.init) if cr.init else None}"
                )
    return 0


def _emit_json(img, do_list, analyze, strings=False) -> int:
    """Machine-readable --list / --analyze / --strings output for scripting."""
    out: dict = {
        "path": img.path,
        "fmt": img.fmt,
        "arch": img.arch.value,
        "base": img.base,
    }
    if do_list:
        out["functions"] = [
            {"va": f.va, "name": f.name, "display": f.display, "kind": f.kind}
            for f in sorted(img.funcs, key=lambda x: x.va)
        ]
    if strings:
        from .re import extract_strings

        out["strings"] = [
            {"va": s.va, "section": s.section, "encoding": s.encoding, "text": s.text}
            for s in extract_strings(img)
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
                "disp": s.disp,
                "size": s.size,
                "value": s.value,
            }
            for s in immediate_stores(img, real)[:16]
        ],
        "call_args": [
            {
                "call_addr": a.call_addr,
                "reg": a.reg,
                "value": a.value,
                "target": a.target,
            }
            for a in call_immediate_args(img, real)[:12]
        ],
        "crc": [
            {"start": cr.start, "end": cr.end, "polys": cr.polys, "init": cr.init}
            for cr in detect_crc_loops(img, real)
        ],
    }


if __name__ == "__main__":
    sys.exit(main())
