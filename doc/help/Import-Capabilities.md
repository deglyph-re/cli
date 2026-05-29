# Import Capabilities

The import detector flags imported APIs that grant a notable capability: process
execution, code injection, memory-protection changes, dynamic code loading,
network access, or anti-debugging. It maps the binary's import table against a
curated list of API names. It runs by default in `deglyph scan`.

## The capability map

| Rule | Capability | Examples | Level |
| --- | --- | --- | --- |
| `import/process-exec` | Run a process or command | `system`, `CreateProcess`, `ShellExecute`, `execve` | warning |
| `import/code-injection` | Inject into another process | `WriteProcessMemory`, `CreateRemoteThread`, `VirtualAllocEx` | warning |
| `import/memory-protect` | Change memory protection | `VirtualProtect`, `mprotect` | note |
| `import/dynamic-load` | Load code at runtime | `LoadLibrary`, `GetProcAddress`, `dlopen` | note |
| `import/network` | Open a network connection | `connect`, `WinHttpOpen`, `WSAStartup`, `curl_easy_init` | note |
| `import/anti-debug` | Detect or resist a debugger | `IsDebuggerPresent`, `ptrace`, `NtQueryInformationProcess` | note |

Names are matched case-insensitively, with the trailing `A` / `W` / `Ex` Windows
variants normalized off, so `CreateProcessW` and `CreateProcessA` both match the
`createprocess` entry.

## A capability, not a misuse

An import hit means the binary **links** an API with a given capability. It does
not mean the API is called, or that any call is malicious. Almost every
non-trivial program loads libraries, opens sockets, or changes memory
protections for legitimate reasons. The value of the list is triage: it surfaces
the binary's reach so you can decide what to inspect, not a verdict.

Process-execution and code-injection imports are `warning` because they are the
highest-signal capabilities to review; the rest are `note`. Read each as "this
binary can do X", then confirm intent in the [disassembly](Disassembly.md) or
with the [AI assistant](AI-Assistant.md) if it matters. See
[Heuristics, Not Proofs](Heuristics.md).

## See also

- [Scanning Binaries](Scanning.md): the scanner overview.
- [Rules Catalog](Rules-Catalog.md): every import rule and its level.
- [Heuristics, Not Proofs](Heuristics.md): capability versus misuse.
