# PEFind

A command-line tool for static analysis that searches for ASCII, Unicode, and hex patterns in files—especially **PE** and **ELF** binaries. It scans files recursively and reports each match with file offset and section context.

## Building

Requires CMake 3.16+ and a C++17 compiler. Builds on Windows, Linux, and macOS.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

On Windows with Visual Studio generators:

```bash
cmake --build build --config Release
```

Run tests:

```bash
ctest --test-dir build
# Windows (Multi-Config):
ctest --test-dir build -C Release
```

## Releases

GitHub Actions builds packages for Windows, Linux, and macOS when you push a version tag:

```bash
git tag v1.2.0
git push origin v1.2.0
```

Published assets (each includes the binary, `README.md`, and `LICENSE`):

- `PEFind-windows-x64.zip` (`PEFind.exe`)
- `PEFind-linux-x64.tar.gz` (`PEFind`)
- `PEFind-macos-universal.tar.gz` (`PEFind`)

To rebuild an existing tag, run the **Release** workflow from the Actions tab and enter the tag name.

## Usage

```
PEFind[.exe] [options] <path> <search_string>
PEFind[.exe] [options] --hex <pattern> <path>
```

On Windows the binary is `PEFind.exe`; on Linux and macOS it is `PEFind`.

Options may appear in any order. In text mode, positional arguments must be `<path>` then `<search_string>`. In hex mode, supply `--hex <pattern>` and `<path>`.

Short flags use one dash (`-a`, `-ci`, `-au`); long flags use two (`--ascii`, `--nocase`). `--hex` has no short form (`-h` is help).

### Options

| Flag | Description |
|------|-------------|
| `-a`, `--ascii` | Search for ASCII strings only |
| `-u`, `--unicode` | Search for Unicode (UTF-16LE) strings only |
| `-au`, `-ua`, `--both` | Search for both ASCII and Unicode (default) |
| `-ci`, `--nocase` | Case-insensitive text search (ASCII/Unicode only) |
| `-c`, `--count` | Show match counts per file instead of individual matches |
| `-n`, `--nth <n>` | Show only the 1-based Nth match from each file |
| `--hex <pattern>` | Search for a hex pattern (e.g. `"4D5A9000"` or `"xx xx 90 00"`) |
| `-s`, `--sort <n>` | Sort results: `0` = filepath, `1` = file offset, `2` = section index, `3` = section offset, `4` = section name, `5` = Format |
| `-h`, `--help` | Show help message |

### Examples

Windows — Unicode search in a folder:

```bash
PEFind.exe -u E:\samples "Setup"
```

Linux — ASCII search with section sorting:

```bash
./PEFind -a -s 4 /usr/bin "HTTP"
```

Case-insensitive search (ASCII + Unicode):

```bash
PEFind.exe -au -ci -s 2 E:\samples "setup"
```

Show only the first match per file:

```bash
./PEFind -n 1 ./binaries "main"
```

Hex search (MZ / PE signature):

```bash
PEFind.exe --hex "4D5A9000" E:\samples
```

Hex search with wildcards and count mode:

```bash
./PEFind --hex "xx xx 90 00" -c /path/to/files
```

ELF section-aware string search:

```bash
./PEFind -a /lib/x86_64-linux-gnu/libc.so.6 "GLIBC"
```

## Notes

- Result columns: `FilePath`, `FileOff`, `SecIndex`, `secOffset`, `secName`, and `Format`.
- Unsorted per-match searches print rows as files finish scanning. `--sort`, `--count`, and `--nth` render after the scan so results can be sorted or consolidated first.
- Every scan ends with statistics: files scanned, files with matches, matches found, result rows, and files with scan errors.
- `--count` keeps those columns and appends `Matches`. Location/section columns describe the earliest counted match in that file.
- `Format` reports binary status: `PE` / `ELF` for in-section matches; overlay messages for recognized binaries with matches outside sections; `Not a PE or ELF file.` otherwise.
- ELF support covers little-endian ELF32 and ELF64 section mapping. Big-endian ELF is not mapped yet.
- Hex patterns must be complete byte pairs and contain at least one exact byte; all-wildcard patterns are rejected.
- `--nocase` applies to ASCII/Unicode only; hex search is always exact.
- `--count` and `--nth` cannot be combined.

## License

MIT — see [LICENSE](LICENSE).
