# WinHTTP Web Downloader (C++23)

A small native Windows console application using WinHTTP and the Windows API. It supports:
- HTTP/HTTPS downloads with WinHTTP
- HTTP byte-range parallel downloads when the server supports ranges
- Single-stream fallback when ranges are unavailable
- Resume via a sidecar `.resume.json`-style state file (simple text format)
- Retries, cancellation (Ctrl+C), progress display, configurable workers/chunk size/timeouts
- Optional SHA-256 verification against a supplied hex digest

## Requirements
- Windows 10/11
- Visual Studio 2022 or newer with the C++ desktop workload and Windows SDK
- CMake 3.24+

## Build
From a Visual Studio Developer PowerShell or a shell with CMake and MSVC available:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
```

The executable is `build\Release\WinHttpWebDownloader.exe` (or the corresponding configuration directory).

## Usage

```powershell
WinHttpWebDownloader.exe "https://example.com/file.zip" "C:\Downloads\file.zip"
WinHttpWebDownloader.exe "https://example.com/file.zip" "C:\Downloads\file.zip" --workers 4 --chunk-mib 8
WinHttpWebDownloader.exe "https://example.com/file.zip" "C:\Downloads\file.zip" --resume
WinHttpWebDownloader.exe "https://example.com/file.zip" "C:\Downloads\file.zip" --sha256 <64-hex-digest>
WinHttpWebDownloader.exe --help
```

Options:
- `--workers N`: parallel workers, 1–32 (default 4)
- `--chunk-mib N`: chunk size in MiB, 1–256 (default 8)
- `--timeout-sec N`: WinHTTP resolve/connect/send/receive timeout (default 60)
- `--retries N`: retries per chunk/request (default 3)
- `--resume`: resume using `<destination>.whrstate`; otherwise stale state is discarded
- `--sha256 HEX`: verify completed output with SHA-256 (CNG/BCrypt)

## Notes and limitations
- Server range support is detected with a `GET Range: bytes=0-0` probe. If it does not return `206 Partial Content` with a valid `Content-Range`, the application uses a single-stream download.
- Parallel downloads require a known content length and range support. The downloader sends `If-Range` with an ETag or Last-Modified validator when available. If a chunk response is inconsistent, it fails safely rather than writing that response into the wrong file offsets.
- Resume currently applies to parallel range downloads; single-stream fallback starts a fresh transfer even when `--resume` is supplied. Resume metadata is tied to URL, expected size, and validator. Chunk completion is tracked in a sidecar file. Do not edit the state file manually.
- Resume is best-effort. A changed URL/resource, server without range support, changed validator, or incomplete metadata causes a fresh download.
- The destination is written directly. A failed download may leave a partial destination file and state sidecar.
- SHA-256 is optional; the server's ETag is not assumed to be a cryptographic checksum.
- This is a testable starter application, not a hardened enterprise download manager. Test against non-critical files first.
