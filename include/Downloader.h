#pragma once

#define NOMINMAX
#include <Windows.h>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace whd
{
    struct DownloadOptions
    {
        unsigned Workers = 4;
        std::uint64_t ChunkBytes = 8ull * 1024 * 1024;
        unsigned TimeoutSeconds = 60;
        unsigned Retries = 3;
        bool Resume = true;
        std::optional<std::wstring> ExpectedSha256;
    };

    struct DownloadProgress
    {
        std::uint64_t BytesReceived = 0;
        std::uint64_t TotalBytes = 0;
        unsigned CompletedChunks = 0;
        unsigned TotalChunks = 0;

        // Bytes transferred in this process, excluding data reused from a prior run.
        std::uint64_t SessionBytesReceived = 0;
        std::uint64_t ResumedBytes = 0;
        unsigned ResumedChunks = 0;
        unsigned RetryCount = 0;
        unsigned ActiveWorkers = 0;
    };

    struct DownloadResult
    {
        bool Success = false;
        std::wstring Message;
        std::uint64_t BytesWritten = 0;
        std::uint64_t TotalBytes = 0;
        unsigned HttpStatus = 0;
    };

    using ProgressCallback = std::function<void(const DownloadProgress&)>;

    DownloadResult Download(
        const std::wstring& url,
        const std::filesystem::path& destination,
        const DownloadOptions& options,
        const ProgressCallback& progress,
        HANDLE cancelEvent);
}
