# PEFind

A command-line tool for static analysis that searches for ASCII, Unicode, and hex patterns in files (especially PE binaries). It scans multiple files recursively and lets you sort results by file path, offset, section index, and more.

## Building

Requires CMake 3.16+ and a C++17 compiler. The scanner itself uses Windows
APIs and is built on Windows; the unit tests are portable and can run on other
platforms.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Unit tests are included and run with `ctest` from the build directory.

## Releases

GitHub Actions builds a Windows release automatically when you push a version tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The workflow runs tests, then publishes `PEFind-windows-x64.zip` (containing `PEFindC1.exe` and `README.md`) to a GitHub Release with auto-generated notes. To rebuild an existing tag, run the **Release** workflow manually from the Actions tab and enter the tag name.

## Usage

```
PEFindC1.exe [options] <path> <search_string>
PEFindC1.exe [options] --hex <pattern> <path>
```

Options may appear in any order. In text mode, positional arguments must be `<path>` then `<search_string>`. In hex mode, supply `--hex <pattern>` and `<path>`.

Short flags use one dash (`-a`, `-ci`, `-au`); long flags use two (`--ascii`, `--nocase`). `--hex` has no short form (`-h` is help).

### Options

| Flag | Description |
|------|-------------|
| `-a`, `--ascii` | Search for ASCII strings only |
| `-u`, `--unicode` | Search for Unicode (wide) strings only |
| `-au`, `-ua`, `--both` | Search for both ASCII and Unicode (default) |
| `-ci`, `--nocase` | Case-insensitive text search (ASCII/Unicode only) |
| `-c`, `--count` | Show match counts per file instead of individual matches |
| `-n`, `--nth <n>` | Show only the 1-based Nth match from each file |
| `--hex <pattern>` | Search for a hex pattern (e.g. `"4D5A9000"` or `"xx xx 90 00"`) |
| `-s`, `--sort <n>` | Sort results: `0` = filepath, `1` = file offset, `2` = section index, `3` = section offset, `4` = section name, `5` = isPE |
| `-h`, `--help` | Show help message |

### Examples

Search for Unicode string "Setup" in a folder:
```bash
PEFindC1.exe -u E:\tmp "Setup"
```

Sort results by file offset:
```bash
PEFindC1.exe -u -s 1 E:\tmp "Setup"
```

Case-insensitive search for both ASCII and Unicode:
```bash
PEFindC1.exe -au -ci -s 2 E:\tmp "Setup"
```

Show only the first match from each file:
```bash
PEFindC1.exe -n 1 E:\tmp "Setup"
```

Search by hex pattern (e.g. MZ header):
```bash
PEFindC1.exe --hex "4D5A9000" E:\tmp
```

Hex search with count mode (options may follow the path):
```bash
PEFindC1.exe --hex "4D5A9000" -c E:\tmp
```

Show match counts per file:
```bash
PEFindC1.exe -c E:\tmp "Setup"
```

## Notes

- ASCII, Unicode, and hex matches use the same result columns: `FilePath`, `FileOff`, `SecIndex`, `secOffset`, `secName`, and `isPE`.
- Unsorted per-match searches print rows as files finish scanning. `--sort`, `--count`, and `--nth` render after the scan so their results can be sorted or consolidated first.
- Every scan ends with statistics for scanned files, files with matches, matches found, displayed result rows, and files with scan errors.
- `--count` keeps those result columns and appends `Matches`. Each count row covers one file, so its location and section columns describe the earliest counted match in that file.
- Invalid PE files and matches outside PE sections are reported in the `isPE` column as `Invalid PE or string not in sections(overlay?)`. Non-PE files use `Not a PE file.`
- Hex patterns must be complete byte pairs and must contain at least one exact byte; all-wildcard patterns are rejected.
- `--nocase` applies to ASCII and Unicode text search only; hex search is always exact.
- `--count` and `--nth` are separate output modes and cannot be combined.
