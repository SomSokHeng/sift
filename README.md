# sift

Static artifact triage and computer-science domain classification, in C.

Answers two questions about any file: **what is this**, and **what area of CS does it belong to**.

Static analysis only. It never executes, patches, or modifies its input.

## Build

```
make
```

C11, no dependencies beyond libm.

## Usage

```
sift [options] <file...>
  -j, --json      JSON output
  -c, --csv       CSV output
  -s, --strings   include sampled strings
  -q, --quiet     suppress per-file text output
```

## Format detection

ELF, ELF core, PE/COFF, Mach-O, Mach-O fat, WebAssembly, Java class, .NET, Python bytecode, Lua bytecode, Dalvik DEX, ZIP, gzip, bzip2, xz, tar, PNG, JPEG, GIF, PDF, SQLite, RIFF, WOFF, and Go binaries.

## CS domain classification

Scores evidence from shared-library names, sampled strings, detected cryptographic constants, and container format, then reports the winning domain with a confidence share:

systems, crypto, network, web, database, ml-ai, media, toolchain, game, reverse, embedded, security, science, finance, mobile.

## Cryptographic constant detection

Scans for well-known algorithm fingerprints that indicate a library implements the primitive itself rather than calling out to one: AES S-box and rcon, SHA-256 round constants and IV, MD5 T-table, ChaCha20 sigma, Base64 alphabet, zlib header, PNG IDAT signature.

Verified against `libcrypto.so`, which reports the AES S-box, ChaCha20 sigma, and Base64 alphabet.

## Hardening analysis

NX and RELRO from the ELF program headers, PIE from ELF type, stack canary from `__stack_chk_fail` in the symbol table, code signing from the PE certificate table. Cross-checked against `readelf`.

## Known limitation

NX is derived from `PT_GNU_STACK` flags in the program header. On some toolchains an executable stack is not recorded in those flags, so a binary built with `-z execstack` can be reported as NX-enabled when `readelf` reports `RWE`. Dynamically linked binaries are classified correctly.

## Safety

Input is bounds-checked throughout. Verified clean under AddressSanitizer and UndefinedBehaviorSanitizer against real binaries, byte-mutated binaries, random data, and truncated files at every length from 4 bytes upward.

## License

Apache-2.0
