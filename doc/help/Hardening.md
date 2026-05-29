# Hardening Posture

The hardening detector reports exploit-mitigation protections that are **missing**
from a binary. It reads the protection flags the container format records, across
PE, ELF, and Mach-O. A fully hardened binary produces no hardening findings, so
silence here is good news. It runs by default in `deglyph scan`.

## What it checks

| Rule | Meaning | Level |
| --- | --- | --- |
| `harden/no-aslr` | ASLR off (no DYNAMIC_BASE / not PIE) | warning |
| `harden/no-dep` | DEP / NX off (data pages executable) | warning |
| `harden/no-stack-canary` | No stack canaries | warning |
| `harden/no-pie` | Not position independent (ELF / Mach-O) | warning |
| `harden/no-relro` | RELRO off (GOT writable, ELF) | warning |
| `harden/partial-relro` | Partial RELRO only (no BIND_NOW) | note |
| `harden/no-cfg` | Control Flow Guard not enabled (PE) | note |
| `harden/no-high-entropy-va` | 64-bit binary lacks high-entropy ASLR (PE) | note |
| `harden/no-safeseh` | SafeSEH table absent (PE32) | note |
| `harden/no-fortify` | FORTIFY_SOURCE variants not detected (ELF) | note |
| `harden/no-bti-pac` | ARM BTI / PAC hints not advertised (ELF) | note |
| `harden/unsigned` | No code signature (PE / Mach-O) | note |

Critical missing protections are `warning`, so they trip the default gate.
Posture improvements are `note`, so they inform without failing the build.

## How it reads each format

The detector inspects format-specific structures rather than decoding code:

- **PE** reads the DLL characteristics (DYNAMIC_BASE, NX_COMPAT, GUARD_CF,
  HIGH_ENTROPY_VA) and the load configuration.
- **ELF** reads the PIE flag, the GNU_STACK permissions, the RELRO segment plus
  BIND_NOW, fortified symbol variants, and the AArch64 GNU property note.
- **Mach-O** reads the PIE header flag and the presence of a code signature.

## Stack canaries on stripped builds

Canary detection is symbol-based across all three formats: the presence of a
stack-guard symbol such as `__stack_chk_fail` or `__security_check_cookie`. On a
PE this would miss a stripped release build that has the protection but no symbol,
so the detector **also** reads the load configuration's security cookie, which a
`/GS` build sets even when stripped. Without that fallback, every stripped PE
would falsely report a missing canary.

## Reading a finding

A hardening "miss" is an **absent flag**, not a demonstrated exploit. It tells you
a mitigation was not enabled, which is worth knowing, but it does not prove the
binary is exploitable. Word findings as posture, not as vulnerabilities. See
[Heuristics, Not Proofs](Heuristics.md).

## See also

- [Scanning Binaries](Scanning.md): the scanner overview.
- [Rules Catalog](Rules-Catalog.md): every rule and its default level.
- [Suppressing Findings](Suppressing-Findings.md): accepting a known posture.
