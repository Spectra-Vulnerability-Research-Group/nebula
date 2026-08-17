# 𝕹𝕰𝕭𝖀𝕷𝕬
Nebula v5.0 is a fully client-side, zero-dependency static analysis engine implemented as a single ~34,000-line HTML file. All analysis executes in the browser; no source code is transmitted externally.

### The Analysis Pipeline
The engine runs five sequential passes over submitted source:
1. Tokenizer (tokenize()): A character-walk lexer that blanks comments and string literals to ASCII spaces while preserving newline positions. Supports language-specific block comment delimiters, line comment prefixes, triple-quoted strings (Python), and backtick strings (JS/PHP/Go). Output is an index-preserving stripped buffer where lineOf(strip, idx) maps any match position back to the original line number.

2. Function segmentation (splitFunctions()): Produces scope objects {start, end, name} for taint containment. Brace-delimited languages (C, C++, Java, JS, Go, Rust) use a depth counter on {/}. Indent-delimited languages (Python, Ruby) use def boundary detection. A module-level scope covering the full file is always appended to catch top-level flows.

3. Taint analysis (taintAnalyze()): Intra-function, flow-sensitive, forward data flow with one level of interprocedural reach. The engine pre-scans function definitions to extract parameter names, then seeds parameter sets as tainted when call sites pass a recognized source. Within each scope, assignments are parsed via parseAssign() which strips declarators (var, let, const, auto, int, etc.) and extracts LHS/RHS. Taint propagates forward when isTaintedExpr(rhs) returns true and isSanitized(rhs) returns false. At each line, all known sinks are checked; when a tainted variable or direct source reaches a sink with no sanitizer on the same line, a confirmed finding is emitted with a prose data-flow trace. Sources, sinks, and sanitizers are defined per-language. Source examples (Python): input(), sys.argv, request.{args,form,json,cookies}, os.environ, recv().
   Sink examples (Python): eval() (CWE-95, critical), os.system() (CWE-78, critical), cursor.execute() (CWE-89, high), open() (CWE-22, high), pickle.loads() (CWE-502, critical).
Sanitizer examples (Python): int(), float(), html.escape(), shlex.quote(), re.escape(), os.path.basename().

5. Rule pass (runRules()): A regex rule library of ~300+ patterns executed over the stripped buffer. Rules are language-gated via ruleAppliesTo() (C-prefix rules apply only to c/cpp/asm/generic, etc.). Each match is capped at 25 per rule per scan. Confidence is review by default, upgraded to high if a taint source pattern appears on the same raw line, or unconditionally high for secret/crypto rule categories (SEC-, CRY-). Rule categories include: hardcoded secrets (AWS keys, private keys, API tokens, passwords), SQL/command/template injection, XSS, XXE, insecure deserialization, weak cryptography (MD5, SHA1, DES, ECB mode, static IVs), CORS/security header misconfigs, C/C++ buffer overflows (strcpy, strcat, gets, sprintf, memcpy, malloc integer overflow), race conditions (TOCTOU patterns), privilege escalation (setuid(0), chmod 777), information disclosure, and exploit development primitives (ROP chain keywords, NOP sleds, shellcode markers, ASLR bypass patterns, vtable overwrites, SROP).

6. Correlation and dedup (correlate()): Merges taint and rule findings. Where a taint finding and a rule finding share the same line and vulnerability class, the taint finding supersedes (taint proves reachability; rule findings are demoted as overlapping via RULE_SINK_OVERLAP). Deduplication keys on (id, line, class). If showReview is disabled, confidence=review findings are filtered. Final sort order: confidence (confirmed → high → review), then severity (critical → high → medium → low → info), then line number. Output includes JSON export.


### Demo
<img width="1231" height="977" alt="image" src="https://github.com/user-attachments/assets/90a2cdb9-c02d-43d5-ac69-258c76502860" />



### Binary Analysis Module
A separate module parses uploaded binary files (ELF, PE, Mach-O) from ArrayBuffer via Uint8Array. It performs: magic byte identification, architecture detection via ELF e_machine and PE Machine fields, endianness detection, entry point extraction from ELF e_entry / PE AddressOfEntryPoint, section count from ELF e_shnum / PE NumberOfSections, and security mitigation checks (NX via PT_GNU_STACK flags, PIE via ELF e_type=ET_DYN, stack canary via __stack_chk_fail string scan, RELRO via GNU_RELRO string, SafeSEH/CFG via Windows-specific strings). String extraction scans printable ASCII runs ≥4 bytes.

⚠️ Known limitations in this module: Symbol detection uses regex matching against the raw binary treated as a Latin-1 string with no section boundary awareness — expect false positives from incidental byte sequences. Stack canary, RELRO, SafeSEH, and CFG detection scan only the first 500 bytes of the file and will miss symbols located beyond that offset in larger binaries. ASLR detection returns a hardcoded heuristic string rather than inspecting actual ELF dynamic flags. ROP gadget addresses are randomly generated at scan time and do not correspond to real offsets in the loaded binary — treat gadget output as a pattern inventory only, not as an actionable address list. The displayed "SHA-256" hash is a 32-bit djb2-style checksum over the first 1,000 bytes, not a real SHA-256 digest. When no gadgets are found via byte matching, a simulated fallback set is injected automatically; this will be replaced with a proper byte-scan implementation in a future release.


### Language Detection
Plurality voting over per-language hint sets (5 hints each). No weighting; ties fall to generic. Supported: Python, PHP, JavaScript/TypeScript, Java, C, C++, Go, Rust, Ruby, Assembly, Generic.

### UI Architecture
Single-panel grid layout. Left panel: source input, language selector, mode toggles (taint tracking, review-level display, engine log, code view, binary analysis, notes), severity counters, sweep animation. Right panel: scrollable findings list with per-finding severity badge, confidence badge, line reference, snippet, description, remediation, and data-flow trace. Export produces structured JSON with CWE mappings, confidence scores, and sanitized data-flow prose.

