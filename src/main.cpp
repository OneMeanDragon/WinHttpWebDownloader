#include "../include/Downloader.h"

#include <Windows.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#include <sstream>
#include <cstdint>

namespace
{
    HANDLE g_cancelEvent = nullptr;

    BOOL WINAPI ConsoleHandler(DWORD event)
    {
        if (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT || event == CTRL_CLOSE_EVENT)
        {
            if (g_cancelEvent)
                SetEvent(g_cancelEvent);
            return TRUE;
        }
        return FALSE;
    }

    std::wstring FormatBytes(std::uint64_t bytes)
    {
        static constexpr const wchar_t* units[] = { L"B", L"KiB", L"MiB", L"GiB", L"TiB" };
        double value = static_cast<double>(bytes);
        std::size_t unit = 0;
        while (value >= 1024.0 && unit + 1 < std::size(units))
        {
            value /= 1024.0;
            ++unit;
        }
        std::wostringstream out;
        out << std::fixed << std::setprecision(unit == 0 ? 0 : 2) << value << L' ' << units[unit];
        return out.str();
    }

    std::wstring FormatDuration(std::uint64_t seconds)
    {
        const auto hours = seconds / 3600;
        const auto minutes = (seconds % 3600) / 60;
        const auto secs = seconds % 60;
        std::wostringstream out;
        if (hours > 0)
            out << std::setfill(L'0') << std::setw(2) << hours << L':'
            << std::setw(2) << minutes << L':' << std::setw(2) << secs;
        else
            out << std::setfill(L'0') << std::setw(2) << minutes << L':' << std::setw(2) << secs;
        return out.str();
    }

    void PrintUsage()
    {
        std::wcout <<
            L"WinHTTP Web Downloader (C++23)\n\n"
            L"Usage:\n"
            L"  WinHttpWebDownloader.exe <url> <destination> [options]\n\n"
            L"Options:\n"
            L"  --workers N       Parallel workers (1-32, default 4)\n"
            L"  --chunk-mib N     Chunk size in MiB (1-256, default 8)\n"
            L"  --timeout-sec N   WinHTTP timeout seconds (default 60)\n"
            L"  --retries N       Additional attempts per failed chunk (default 3)\n"
            L"  --resume          Resume using destination.whrstate (default)\n"
            L"  --fresh           Ignore existing state and start over\n"
            L"  --sha256 HEX      Verify SHA-256 after download\n"
            L"  --help            Show this help\n";
    }

    bool ParseUnsigned(std::wstring_view text, unsigned& value)
    {
        if (text.empty())
            return false;
        unsigned long parsed = 0;
        for (wchar_t ch : text)
        {
            if (ch < L'0' || ch > L'9')
                return false;
            parsed = parsed * 10 + static_cast<unsigned long>(ch - L'0');
            if (parsed > 1000000)
                return false;
        }
        value = static_cast<unsigned>(parsed);
        return true;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && (std::wstring_view(argv[1]) == L"--help" || std::wstring_view(argv[1]) == L"-h"))
    {
        PrintUsage();
        return 0;
    }
    if (argc < 3)
    {
        PrintUsage();
        return 2;
    }

    whd::DownloadOptions options;
    for (int i = 3; i < argc; ++i)
    {
        const std::wstring_view arg = argv[i];
        auto takeNumber = [&](unsigned& target) -> bool
            {
                if (i + 1 >= argc || !ParseUnsigned(argv[i + 1], target))
                    return false;
                ++i;
                return true;
            };

        if (arg == L"--workers")
        {
            if (!takeNumber(options.Workers) || options.Workers < 1 || options.Workers > 32)
            {
                std::wcerr << L"Invalid --workers value.\n";
                return 2;
            }
        }
        else if (arg == L"--chunk-mib")
        {
            unsigned mib = 0;
            if (!takeNumber(mib) || mib < 1 || mib > 256)
            {
                std::wcerr << L"Invalid --chunk-mib value.\n";
                return 2;
            }
            options.ChunkBytes = static_cast<std::uint64_t>(mib) * 1024 * 1024;
        }
        else if (arg == L"--timeout-sec")
        {
            if (!takeNumber(options.TimeoutSeconds) || options.TimeoutSeconds < 1 || options.TimeoutSeconds > 3600)
            {
                std::wcerr << L"Invalid --timeout-sec value.\n";
                return 2;
            }
        }
        else if (arg == L"--retries")
        {
            if (!takeNumber(options.Retries) || options.Retries > 20)
            {
                std::wcerr << L"Invalid --retries value.\n";
                return 2;
            }
        }
        else if (arg == L"--resume")
        {
            options.Resume = true;
        }
        else if (arg == L"--fresh")
        {
            options.Resume = false;
        }
        else if (arg == L"--sha256")
        {
            if (i + 1 >= argc)
            {
                std::wcerr << L"Missing --sha256 digest.\n";
                return 2;
            }
            options.ExpectedSha256 = argv[++i];
        }
        else
        {
            std::wcerr << L"Unknown option: " << arg << L"\n";
            return 2;
        }
    }

    g_cancelEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_cancelEvent)
    {
        std::wcerr << L"CreateEventW failed: " << GetLastError() << L"\n";
        return 1;
    }
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    const auto started = std::chrono::steady_clock::now();
    std::wcerr << L"Connecting and checking server support...\n";
    const auto result = whd::Download(argv[1], argv[2], options,
        [started](const whd::DownloadProgress& p)
        {
            const auto now = std::chrono::steady_clock::now();
            const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - started).count();
            const double elapsedSeconds = std::max(0.001,
                std::chrono::duration<double>(now - started).count());
            // Speed is based only on bytes transferred in this run, not resumed data.
            const double bytesPerSecond = static_cast<double>(p.SessionBytesReceived) / elapsedSeconds;
            const double percent = p.TotalBytes
                ? std::clamp(100.0 * static_cast<double>(p.BytesReceived) / static_cast<double>(p.TotalBytes), 0.0, 100.0)
                : 0.0;
            const unsigned barWidth = 28;
            const unsigned filled = p.TotalBytes
                ? static_cast<unsigned>(percent * barWidth / 100.0) : 0;

            std::wcerr << L"\r[";
            for (unsigned i = 0; i < barWidth; ++i)
                std::wcerr << (i < filled ? L'=' : (i == filled && filled < barWidth ? L'>' : L' '));
            std::wcerr << L"] ";
            if (p.TotalBytes)
                std::wcerr << std::fixed << std::setprecision(1) << std::setw(5) << percent << L"%  ";
            else
                std::wcerr << L"  ?%  ";

            std::wcerr << FormatBytes(p.BytesReceived) << L" / ";
            if (p.TotalBytes) std::wcerr << FormatBytes(p.TotalBytes);
            else std::wcerr << L"unknown size";
            std::wcerr << L"  |  ";
            if (bytesPerSecond >= 1024.0 * 1024.0)
                std::wcerr << std::fixed << std::setprecision(2) << bytesPerSecond / (1024.0 * 1024.0) << L" MiB/s";
            else
                std::wcerr << std::fixed << std::setprecision(1) << bytesPerSecond / 1024.0 << L" KiB/s";
            std::wcerr << L"  |  elapsed " << FormatDuration(static_cast<std::uint64_t>(std::max<std::int64_t>(0, elapsed)));

            if (p.TotalBytes && bytesPerSecond > 0.0 && p.BytesReceived < p.TotalBytes)
            {
                const auto remaining = static_cast<std::uint64_t>(
                    static_cast<double>(p.TotalBytes - p.BytesReceived) / bytesPerSecond);
                std::wcerr << L"  |  ETA " << FormatDuration(remaining);
            }
            else if (p.TotalBytes && p.BytesReceived >= p.TotalBytes)
                std::wcerr << L"  |  ETA 00:00";
            else
                std::wcerr << L"  |  ETA calculating";

            if (p.TotalChunks)
                std::wcerr << L"  |  chunks " << p.CompletedChunks << L"/" << p.TotalChunks;
            if (p.ResumedChunks)
                std::wcerr << L"  |  resumed " << p.ResumedChunks << L" chunks ("
                << FormatBytes(p.ResumedBytes) << L")";
            if (p.RetryCount)
                std::wcerr << L"  |  retries " << p.RetryCount;
            if (p.TotalChunks)
                std::wcerr << L"  |  workers " << p.ActiveWorkers;
            std::wcerr << L"   " << std::flush;
        }, g_cancelEvent);

    std::wcerr << L"\n";
    SetConsoleCtrlHandler(ConsoleHandler, FALSE);
    CloseHandle(g_cancelEvent);
    g_cancelEvent = nullptr;

    if (!result.Success)
    {
        std::wcerr << L"Download failed: " << result.Message
            << L" (HTTP " << result.HttpStatus << L")\n";
        return 1;
    }

    std::wcout << L"Download complete: " << argv[2] << L"\n"
        << L"Bytes: " << result.BytesWritten << L"\n";
    if (!result.Message.empty())
        std::wcout << result.Message << L"\n";
    return 0;
}
