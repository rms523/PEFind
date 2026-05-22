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

## Usage

```
PEFindC1.exe [options] <path> <search_string>
PEFindC1.exe [options] --hex "<hex_pattern>" <path>
```

### Options

| Flag | Description |
|------|-------------|
| `-a`, `--ascii` | Search for ASCII strings only |
| `-u`, `--unicode` | Search for Unicode (wide) strings only |
| `-au`, `--both` | Search for both ASCII and Unicode (default) |
| `-ci`, `--nocase` | Case-insensitive search |
| `-c`, `--count` | Show match counts per file instead of individual matches |
| `-n <n>`, `--nth <n>` | Show only the 1-based Nth match from each file |
| `--hex <pattern>` | Search for a hex pattern (e.g. `"4D5A9000"` or `"xx xx 90 00"`) |
| `-s <n>`, `--sort <n>` | Sort results: `0` = filepath, `1` = file offset, `2` = section index, etc. |
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

Show match counts per file:
```bash
PEFindC1.exe -c E:\tmp "Setup"
```

## Notes

- ASCII, Unicode, and hex matches use the same result columns: `FilePath`, `FileOff`, `SecIndex`, `secOffset`, `secName`, and `isPE`.
- `--count` keeps those result columns and appends `Matches`. Each count row covers one file, so its location and section columns describe the earliest counted match in that file.
- Invalid PE files and matches outside PE sections are reported in the `isPE` column as `Invalid PE or string not in sections(overlay?)`.
- Hex patterns must be complete byte pairs and must contain at least one exact byte; all-wildcard patterns are rejected.
- `--count` and `--nth` are separate output modes and cannot be combined.
