# SPDX-License-Identifier: GPL-3.0-or-later
# deglyph
"""`deglyph scan`: secret, import-capability, and baseline-drift detection."""

from __future__ import annotations

import json
import os

import pytest

from deglyph import scan
from deglyph.cli import main
from deglyph.core.image import Func, Image, Section

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "demo.exe")


def _rules(findings):
    return {f.rule for f in findings}


def test_provider_and_keyword_secrets(code_image):
    blob = (
        b"\x90harmless\x00"
        b"-----BEGIN RSA PRIVATE KEY-----\x00"
        b"AKIAIOSFODNN7EXAMPLE\x00"
        b"password=hunter2hunter2\x00"
    )
    img = code_image(blob)
    findings = scan.scan_image(img)
    rules = _rules(findings)
    assert "secret/private-key" in rules
    assert "secret/aws-access-key" in rules
    assert "secret/credential-keyword" in rules
    # the private key and aws key are error-level
    assert any(f.level == "error" for f in findings)
    # offsets resolve to a VA in the .text section (base 0, va 0x1000)
    pk = next(f for f in findings if f.rule == "secret/private-key")
    assert pk.where.startswith("0x")


def test_bare_credential_keyword_does_not_fire(code_image):
    # A keyword with no value is a struct field / env-var name / scheme word,
    # not a leak. These are the strings that flooded real-binary scans.
    blob = b"\x00".join(
        [
            b"\x90",
            b"Bearer ",
            b"client_secret",
            b"password",
            b"AWS_ACCESS_KEY_ID",
            b"CLIENT_TRAFFIC_SECRET_0",
            b"client_id=%s&client_secret=%s&grant_type=refresh_token",
            b"envoy/extensions/transport_sockets/tls/v3/secret.proto",
            b"?password@QAuthenticator@@QEBA?AVQString@@XZ",
        ]
    )
    img = code_image(blob)
    assert "secret/credential-keyword" not in _rules(scan.scan_image(img))


def test_credential_fires_on_assigned_and_embedded_values(code_image):
    # Assignment form and a value-shaped token carrying the keyword both fire.
    for blob in (
        b"\x90password=hunter2hunter2\x00",
        b"\x90secret_key: aB3xK9zQ2mLp7Rt5Vw\x00",
        b"\x90S3cr3t-demo-API-key-do-not-ship\x00",
    ):
        img = code_image(blob)
        assert "secret/credential-keyword" in _rules(scan.scan_image(img)), blob


def test_provider_token_formats(code_image):
    cases = {
        "secret/stripe-key": b"sk_live_4eC39HqLyjWDarjtT1zdp7dcAB",
        "secret/gitlab-pat": b"glpat-ABCDEFGHIJKLMNOPQRST",
        "secret/npm-token": b"npm_" + b"a1B2c3D4e5" * 3 + b"abcdef",
        "secret/openai-key": b"sk-proj-" + b"aB3xK9zQ2m" * 4,
        "secret/slack-webhook": b"https://hooks.slack.com/services/T0/B0/abcdEFGH1234",
    }
    for rule, tok in cases.items():
        img = code_image(b"\x90" + tok + b"\x00")
        assert rule in _rules(scan.scan_image(img)), rule


def test_ignore_filters_by_exact_rule(code_image):
    img = code_image(b"\x90password=hunter2hunter2\x00AKIAIOSFODNN7EXAMPLE\x00")
    rules = _rules(scan.scan_image(img, ignore={"secret/credential-keyword"}))
    assert "secret/credential-keyword" not in rules
    # an unrelated rule is untouched
    assert "secret/aws-access-key" in rules


def test_ignore_category_prefix(code_image):
    img = code_image(b"\x90password=hunter2hunter2\x00AKIAIOSFODNN7EXAMPLE\x00")
    rules = _rules(scan.scan_image(img, ignore={"secret/"}))
    assert not any(r.startswith("secret/") for r in rules)


def test_to_json_has_summary_and_fingerprints(code_image):
    img = code_image(b"\x90password=hunter2hunter2\x00AKIAIOSFODNN7EXAMPLE\x00")
    findings = scan.scan_image(img)
    doc = scan.to_json([("a.bin", findings)], version="1.2")
    assert doc["tool"] == "deglyph" and doc["version"] == "1.2"
    assert doc["summary"]["findings"] == len(findings)
    fps = [f["fingerprint"] for f in doc["files"][0]["findings"]]
    assert fps and all(len(fp) == 12 for fp in fps)


def test_ignore_file_rules_and_fingerprints(tmp_path, code_image):
    img = code_image(b"\x90password=hunter2hunter2\x00AKIAIOSFODNN7EXAMPLE\x00")
    cred = next(
        f for f in scan.scan_image(img) if f.rule == "secret/credential-keyword"
    )
    fp = scan.fingerprint_of(cred)
    p = tmp_path / ".deglyphignore"
    p.write_text(f"# team baseline\nfingerprint: {fp}\nsecret/aws-access-key\n")

    rules, fps = scan.load_ignore_file(str(p))
    assert "secret/aws-access-key" in rules and fp in fps
    out = _rules(scan.scan_image(img, ignore=rules, ignore_fp=fps))
    assert "secret/credential-keyword" not in out
    assert "secret/aws-access-key" not in out


def test_entropy_is_opt_in(code_image):
    # 36 chars, mixed, opaque
    token = b"deKx9aQ2ZpL7mWvR4tYbN6cF8sHjUgEdT3Po"
    img = code_image(b"\x90" + token + b"\x00")
    assert "secret/high-entropy" not in _rules(scan.scan_image(img))
    assert "secret/high-entropy" in _rules(scan.scan_image(img, entropy=True))


def test_entropy_skips_paths_and_symbols(code_image):
    blob = b"C:\\buildroot\\x86_64-1310-posix-seh-msvcrt-rt_v11-rev1\\build\x00"
    img = code_image(blob)
    assert "secret/high-entropy" not in _rules(scan.scan_image(img, entropy=True))


def test_suspicious_imports(code_image):
    img = code_image(bytes.fromhex("c3"))
    img.funcs.append(Func(name="WriteProcessMemory", va=0x2000, kind="import"))
    img.funcs.append(
        Func(name="CreateProcessW", va=0x2008, kind="import")
        # 'w' suffix
    )
    # benign
    img.funcs.append(Func(name="memcpy", va=0x2010, kind="import"))
    img.reindex()
    findings = scan.scan_imports(img)
    rules = _rules(findings)
    assert "import/code-injection" in rules
    assert "import/process-exec" in rules
    assert all("memcpy" not in f.message for f in findings)


def test_diff_baseline(code_image):
    base = code_image(bytes.fromhex("c3"))
    base.funcs.append(Func(name="old_helper", va=0x3000, kind="func"))
    base.reindex()

    cur = code_image(bytes.fromhex("c3"))
    cur.funcs.append(Func(name="new_helper", va=0x3000, kind="func"))
    cur.funcs.append(Func(name="LoadLibraryA", va=0x4000, kind="import"))
    cur.reindex()

    findings = scan.diff_baseline(cur, base)
    msgs = " ".join(f"{f.rule} {f.message}" for f in findings)
    assert "diff/added-function" in msgs and "new_helper" in msgs
    assert "diff/removed-function" in msgs and "old_helper" in msgs
    assert "diff/added-import" in msgs and "LoadLibraryA" in msgs


def test_clean_image_has_no_secret_or_import_findings(code_image):
    img = code_image(bytes.fromhex("90 90 c3"))
    findings = scan.scan_image(img)
    assert not any(f.level in ("error", "warning") for f in findings)
    assert scan.worst_level([("x", findings)]) in (None, "note")


def test_sarif_document_shape(code_image):
    img = code_image(b"-----BEGIN EC PRIVATE KEY-----\x00")
    doc = scan.to_sarif([("a.bin", scan.scan_image(img))], version="9.9")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "deglyph"
    assert run["tool"]["driver"]["version"] == "9.9"
    res = run["results"][0]
    assert res["ruleId"] == "secret/private-key"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "a.bin"


def test_badge_clean_is_green():
    badge = scan.to_badge([("a.bin", [])])
    assert badge["schemaVersion"] == 1
    assert badge["label"] == "deglyph"
    assert badge["message"] == "clean" and badge["color"] == "brightgreen"


def test_badge_counts_worst_first_and_colors_by_worst():
    findings = [
        scan.Finding("r/a", "warning", "m", "0x1"),
        scan.Finding("r/b", "warning", "m", "0x2"),
        scan.Finding("r/c", "error", "m", "0x3"),
        scan.Finding("r/d", "note", "m", "0x4"),
    ]
    badge = scan.to_badge([("a.bin", findings)])
    assert badge["message"] == "1 error, 2 warnings, 1 note"
    assert badge["color"] == "red"


# --- CLI integration over the committed demo binary -------------------------


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_cli_scan_demo_finds_secret_and_exits_nonzero(capsys):
    code = main(["scan", SAMPLE])
    out = capsys.readouterr().out
    assert "S3cr3t-demo-API-key-do-not-ship" in out
    # a warning-level secret fails the default gate
    assert code == 1


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_cli_scan_sarif_is_valid_json(capsys):
    main(["scan", SAMPLE, "--sarif"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert any(
        r["ruleId"] == "secret/credential-keyword" for r in doc["runs"][0]["results"]
    )


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_cli_scan_json_format(capsys):
    main(["scan", SAMPLE, "--format", "json", "--fail-on", "never"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["tool"] == "deglyph"
    assert doc["summary"]["findings"] >= 1
    assert doc["files"][0]["findings"][0]["fingerprint"]


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_cli_scan_badge_format(capsys):
    main(["scan", SAMPLE, "--format", "badge", "--fail-on", "never"])
    badge = json.loads(capsys.readouterr().out)
    assert badge["schemaVersion"] == 1 and badge["label"] == "deglyph"
    # the demo binary plants a secret, so the badge is not clean
    assert badge["message"] != "clean"


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_cli_scan_fail_on_never_exits_zero(capsys):
    assert main(["scan", SAMPLE, "--fail-on", "never"]) == 0
    capsys.readouterr()


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_cli_scan_markdown_format(capsys):
    main(["scan", SAMPLE, "--format", "markdown", "--fail-on", "never"])
    out = capsys.readouterr().out
    assert out.startswith("## deglyph scan:")
    assert "deglyph.dev" in out


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_cli_scan_html_format_self_contained(capsys):
    main(["scan", SAMPLE, "--format", "html", "--fail-on", "never"])
    out = capsys.readouterr().out
    assert out.startswith("<!doctype html>")
    assert "<style>" in out
    assert "<script" not in out


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_cli_scan_output_to_file(tmp_path, capsys):
    out_path = tmp_path / "report.md"
    main(
        [
            "scan",
            SAMPLE,
            "--format",
            "markdown",
            "--output",
            str(out_path),
            "--fail-on",
            "never",
        ]
    )
    assert out_path.read_text(encoding="utf-8").startswith("## deglyph scan:")
    # stdout should be empty when --output captures the report.
    assert capsys.readouterr().out == ""


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_cli_sbom_cyclonedx(capsys):
    assert main(["sbom", SAMPLE]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_cli_sbom_spdx(capsys):
    assert main(["sbom", SAMPLE, "--format", "spdx"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["spdxVersion"] == "SPDX-2.3"


@pytest.mark.skipif(not os.path.isfile(SAMPLE), reason="demo.exe not built")
def test_cli_sbom_output_file(tmp_path, capsys):
    out_path = tmp_path / "sbom.json"
    main(["sbom", SAMPLE, "--output", str(out_path)])
    doc = json.loads(out_path.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert capsys.readouterr().out == ""
# --- Section 6: category, rule-config, hardening evidence, baseline identity ---
def test_finding_category_from_rule():
    from deglyph.scan import _category

    assert _category("harden/no-pie") == "fact"
    assert _category("lib/detected") == "fact"
    assert _category("secret/jwt") == "heuristic"
    assert _category("import/network") == "heuristic"
    assert _category("diff/added-function") == "policy"
    assert _category("cve/known") == "policy"
    # auto-populated on construction
    assert Finding("secret/jwt", "warning", "x", "y").category == "heuristic"


def test_to_json_and_sarif_carry_category():
    f = Finding("harden/no-pie", "warning", "no PIE", "hardening")
    doc = to_json([("a.bin", [f])])
    assert doc["files"][0]["findings"][0]["category"] == "fact"
    sarif = to_sarif([("a.bin", [f])])
    res = sarif["runs"][0]["results"][0]
    assert res["properties"]["category"] == "fact"


def test_to_text_groups_by_category():
    findings = [
        Finding("harden/no-pie", "warning", "no PIE", "hardening"),
        Finding("import/network", "note", "net", "import"),
    ]
    text = to_text([("a.bin", findings)])
    assert "Facts" in text and "Heuristics" in text
    # the fact group appears before the heuristic group
    assert text.index("Facts") < text.index("Heuristics")


def test_rule_config_off_and_retune():
    from deglyph.scan import _apply_rule_config

    findings = [
        Finding("harden/no-cfg", "note", "cfg", "hardening"),
        Finding("harden/unsigned", "note", "unsigned", "hardening"),
    ]
    out = _apply_rule_config(
        findings, {"harden/no-cfg": "off", "harden/unsigned": "error"}
    )
    rules = {f.rule: f.level for f in out}
    assert "harden/no-cfg" not in rules
    assert rules["harden/unsigned"] == "error"


def test_load_rule_config_parses_json(tmp_path):
    from deglyph.scan import load_rule_config

    p = tmp_path / ".deglyphrules"
    p.write_text(
        '{"rules": {"secret/jwt": {"level": "error"}, "harden/no-cfg": '
        '{"level": "off"}, "bogus": {"level": "nonsense"}}}',
        encoding="utf-8",
    )
    cfg = load_rule_config(str(p))
    assert cfg == {"secret/jwt": "error", "harden/no-cfg": "off"}


def test_load_rule_config_missing_file_is_empty(tmp_path):
    from deglyph.scan import load_rule_config

    assert load_rule_config(str(tmp_path / "nope.json")) == {}


def test_hardening_evidence_in_message():
    # A synthetic ELF-ish image is hard to build here; assert the _h helper
    # threads evidence into the message.
    from deglyph.scan import _h

    f = _h("harden/no-pie", evidence="e_type is ET_EXEC, not ET_DYN")
    assert "ET_EXEC" in f.message
    assert f.category == "fact"


def test_import_rationale_in_message(code_image):
    img = code_image(bytes.fromhex("c3"))
    img.funcs.append(Func(name="VirtualProtect", va=0x2000, kind="import"))
    img.reindex()
    hits = scan.scan_imports(img)
    vp = next(h for h in hits if "VirtualProtect" in h.message)
    assert "benign" in vp.message
    assert vp.category == "heuristic"


def _scan_img(code: bytes, name: str) -> Image:
    # a one-section image with one recovered function, for baseline-diff tests.
    import tempfile

    from deglyph.core.image import Arch

    p = tempfile.mktemp()
    with open(p, "wb") as fh:
        fh.write(code)
    img = Image(path=p, fmt="RAW", arch=Arch.X64, base=0)
    img.sections.append(
        Section(
            name=".text",
            va=0x1000,
            size=len(code),
            raw_off=0,
            raw_size=len(code),
            flags="RX",
        )
    )
    img.funcs.append(Func(name=name, va=0x1000, kind="sub"))
    img.reindex()
    return img


def test_baseline_identity_ignores_sub_va_churn():
    # Two builds with the same function body but different sub_ names hash to the
    # same structural identity, so the diff does not see removed + added.
    # xor eax, eax ; ret
    code = b"\x31\xc0\xc3"
    a = _scan_img(code, "sub_1000")
    b = _scan_img(code, "sub_2000")
    ida = scan._func_identity(a, 0x1000)
    assert ida.startswith("shape:") and ida == scan._func_identity(b, 0x1000)
    fn_diffs = [f for f in scan.diff_baseline(a, b) if "function" in f.rule]
    assert not fn_diffs
