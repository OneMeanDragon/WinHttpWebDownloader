#include "../include/Downloader.h"

#include <Windows.h>
#include <winhttp.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <condition_variable>
#include <deque>
#include <functional>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace whd
{
    namespace
    {
        class WinHandle
        {
        public:
            WinHandle() = default;
            explicit WinHandle(HANDLE h) : h_(h) {}
            ~WinHandle() { reset(); }
            WinHandle(const WinHandle&) = delete;
            WinHandle& operator=(const WinHandle&) = delete;
            WinHandle(WinHandle&& other) noexcept : h_(other.release()) {}
            WinHandle& operator=(WinHandle&& other) noexcept
            {
                if (this != &other) reset(other.release());
                return *this;
            }
            HANDLE get() const { return h_; }
            explicit operator bool() const { return h_ && h_ != INVALID_HANDLE_VALUE; }
            HANDLE release() { HANDLE t = h_; h_ = nullptr; return t; }
            void reset(HANDLE h = nullptr) { if (h_ && h_ != INVALID_HANDLE_VALUE) CloseHandle(h_); h_ = h; }
        private:
            HANDLE h_ = nullptr;
        };

        class HInternet
        {
        public:
            HInternet() = default;
            explicit HInternet(HINTERNET h) : h_(h) {}
            ~HInternet() { if (h_) WinHttpCloseHandle(h_); }
            HInternet(const HInternet&) = delete;
            HInternet& operator=(const HInternet&) = delete;
            HInternet(HInternet&& other) noexcept : h_(other.h_) { other.h_ = nullptr; }
            HInternet& operator=(HInternet&& other) noexcept
            {
                if (this != &other)
                {
                    if (h_) WinHttpCloseHandle(h_);
                    h_ = other.h_;
                    other.h_ = nullptr;
                }
                return *this;
            }
            HINTERNET get() const { return h_; }
            explicit operator bool() const { return h_ != nullptr; }
        private:
            HINTERNET h_ = nullptr;
        };

        struct ParsedUrl
        {
            std::wstring Host;
            std::wstring Path;
            INTERNET_PORT Port = 0;
            bool Secure = false;
        };

        bool ParseUrl(const std::wstring& url, ParsedUrl& out)
        {
            URL_COMPONENTS c{};
            c.dwStructSize = sizeof(c);
            c.dwSchemeLength = static_cast<DWORD>(-1);
            c.dwHostNameLength = static_cast<DWORD>(-1);
            c.dwUrlPathLength = static_cast<DWORD>(-1);
            c.dwExtraInfoLength = static_cast<DWORD>(-1);
            if (!WinHttpCrackUrl(url.c_str(), 0, 0, &c))
                return false;
            if (c.nScheme != INTERNET_SCHEME_HTTP && c.nScheme != INTERNET_SCHEME_HTTPS)
                return false;
            out.Host.assign(c.lpszHostName, c.dwHostNameLength);
            out.Path.assign(c.lpszUrlPath, c.dwUrlPathLength);
            if (c.dwExtraInfoLength)
                out.Path.append(c.lpszExtraInfo, c.dwExtraInfoLength);
            if (out.Path.empty()) out.Path = L"/";
            out.Port = c.nPort;
            out.Secure = c.nScheme == INTERNET_SCHEME_HTTPS;
            return !out.Host.empty();
        }

        std::wstring WinErrorText(DWORD error)
        {
            return L"Win32 error " + std::to_wstring(error);
        }

        bool QueryNumber(HINTERNET request, DWORD query, std::uint64_t& value)
        {
            wchar_t buffer[64]{};
            DWORD bytes = sizeof(buffer);
            if (!WinHttpQueryHeaders(request, query | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, buffer, &bytes, WINHTTP_NO_HEADER_INDEX))
                return false;
            value = *reinterpret_cast<DWORD*>(buffer);
            return true;
        }

        std::wstring QueryHeader(HINTERNET request, DWORD query)
        {
            DWORD bytes = 0;
            WinHttpQueryHeaders(request, query, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &bytes, WINHTTP_NO_HEADER_INDEX);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || !bytes)
                return {};
            std::wstring value(bytes / sizeof(wchar_t), L'\0');
            if (!WinHttpQueryHeaders(request, query, WINHTTP_HEADER_NAME_BY_INDEX,
                value.data(), &bytes, WINHTTP_NO_HEADER_INDEX))
                return {};
            while (!value.empty() && value.back() == L'\0') value.pop_back();
            return value;
        }

        bool ParseContentRange(const std::wstring& value, std::uint64_t& start,
            std::uint64_t& end, std::uint64_t& total)
        {
            // Expected: bytes 0-0/123
            if (value.rfind(L"bytes ", 0) != 0) return false;
            const auto dash = value.find(L'-', 6);
            const auto slash = value.find(L'/', dash == std::wstring::npos ? 6 : dash + 1);
            if (dash == std::wstring::npos || slash == std::wstring::npos) return false;
            auto parse = [](std::wstring_view s, std::uint64_t& n)
                {
                    if (s.empty()) return false;
                    n = 0;
                    for (wchar_t c : s)
                    {
                        if (c < L'0' || c > L'9') return false;
                        const auto digit = static_cast<std::uint64_t>(c - L'0');
                        if (n > (std::numeric_limits<std::uint64_t>::max() - digit) / 10) return false;
                        n = n * 10 + digit;
                    }
                    return true;
                };
            return parse(std::wstring_view(value).substr(6, dash - 6), start) &&
                parse(std::wstring_view(value).substr(dash + 1, slash - dash - 1), end) &&
                parse(std::wstring_view(value).substr(slash + 1), total) &&
                end >= start && total > end;
        }

        struct Probe
        {
            bool RangeSupported = false;
            std::uint64_t Size = 0;
            unsigned Status = 0;
            std::wstring ValidatorHeader;
            std::wstring ValidatorValue;
        };

        bool OpenRequest(const ParsedUrl& url, HINTERNET session, HInternet& connection,
            HInternet& request, const std::wstring& verb = L"GET")
        {
            connection = HInternet(WinHttpConnect(session, url.Host.c_str(), url.Port, 0));
            if (!connection) return false;
            request = HInternet(WinHttpOpenRequest(connection.get(), verb.c_str(), url.Path.c_str(),
                nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                url.Secure ? WINHTTP_FLAG_SECURE : 0));
            return static_cast<bool>(request);
        }

        Probe ProbeServer(HINTERNET session, const ParsedUrl& url, unsigned timeout)
        {
            Probe p;
            HInternet connection(WinHttpConnect(session, url.Host.c_str(), url.Port, 0));
            if (!connection) return p;
            HInternet request(WinHttpOpenRequest(connection.get(), L"GET", url.Path.c_str(), nullptr,
                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, url.Secure ? WINHTTP_FLAG_SECURE : 0));
            if (!request) return p;
            std::wstring range = L"Range: bytes=0-0\r\n";
            if (!WinHttpAddRequestHeaders(request.get(), range.c_str(), static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD))
                return p;
            if (!WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
                !WinHttpReceiveResponse(request.get(), nullptr))
                return p;

            std::uint64_t status = 0;
            QueryNumber(request.get(), WINHTTP_QUERY_STATUS_CODE, status);
            p.Status = static_cast<unsigned>(status);
            const auto cr = QueryHeader(request.get(), WINHTTP_QUERY_CONTENT_RANGE);
            std::uint64_t start = 0, end = 0, total = 0;
            if (p.Status == 206 && ParseContentRange(cr, start, end, total) && start == 0 && end == 0)
            {
                p.RangeSupported = true;
                p.Size = total;
            }
            else if (p.Status == 200)
            {
                std::uint64_t size = 0;
                if (QueryNumber(request.get(), WINHTTP_QUERY_CONTENT_LENGTH, size))
                    p.Size = size;
            }
            p.ValidatorValue = QueryHeader(request.get(), WINHTTP_QUERY_ETAG);
            if (!p.ValidatorValue.empty())
                p.ValidatorHeader = L"If-Range: " + p.ValidatorValue + L"\r\n";
            else
            {
                p.ValidatorValue = QueryHeader(request.get(), WINHTTP_QUERY_LAST_MODIFIED);
                if (!p.ValidatorValue.empty())
                    p.ValidatorHeader = L"If-Range: " + p.ValidatorValue + L"\r\n";
            }
            return p;
        }

        bool Cancelled(HANDLE event)
        {
            return event && WaitForSingleObject(event, 0) == WAIT_OBJECT_0;
        }

        bool ReadResponse(HINTERNET request, std::vector<std::byte>& buffer,
            std::uint64_t expected, std::uint64_t& received, HANDLE cancelEvent,
            std::atomic<std::uint64_t>& bytesReceived, std::atomic<std::uint64_t>& sessionBytesReceived,
            const std::function<void()>& reportProgress, std::wstring& error)
        {
            received = 0;
            std::array<std::byte, 64 * 1024> block{};
            while (true)
            {
                if (Cancelled(cancelEvent))
                {
                    error = L"Cancelled";
                    return false;
                }
                DWORD available = 0;
                if (!WinHttpQueryDataAvailable(request, &available))
                {
                    error = WinErrorText(GetLastError());
                    return false;
                }
                if (!available) break;
                while (available)
                {
                    DWORD read = 0;
                    const DWORD ask = static_cast<DWORD>(std::min<std::size_t>(block.size(), available));
                    if (!WinHttpReadData(request, block.data(), ask, &read))
                    {
                        error = WinErrorText(GetLastError());
                        return false;
                    }
                    if (!read) break;
                    if (received + read > expected)
                    {
                        error = L"Server sent more bytes than requested";
                        return false;
                    }
                    buffer.insert(buffer.end(), block.begin(), block.begin() + read);
                    received += read;
                    bytesReceived.fetch_add(read, std::memory_order_relaxed);
                    sessionBytesReceived.fetch_add(read, std::memory_order_relaxed);
                    if (reportProgress) reportProgress();
                    available -= read;
                }
            }
            if (received != expected)
            {
                error = L"Response byte count did not match requested range";
                return false;
            }
            return true;
        }

        bool WriteAt(HANDLE file, std::uint64_t offset, const std::byte* data, std::size_t size, std::wstring& error)
        {
            std::size_t done = 0;
            while (done < size)
            {
                WinHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
                if (!event)
                {
                    error = WinErrorText(GetLastError());
                    return false;
                }
                OVERLAPPED ov{};
                ov.hEvent = event.get();
                const std::uint64_t position = offset + done;
                ov.Offset = static_cast<DWORD>(position & 0xffffffffu);
                ov.OffsetHigh = static_cast<DWORD>(position >> 32);
                DWORD written = 0;
                const DWORD amount = static_cast<DWORD>(std::min<std::size_t>(size - done, MAXDWORD));
                if (!WriteFile(file, data + done, amount, &written, &ov))
                {
                    const DWORD writeError = GetLastError();
                    if (writeError != ERROR_IO_PENDING || !GetOverlappedResult(file, &ov, &written, TRUE))
                    {
                        error = WinErrorText(writeError == ERROR_IO_PENDING ? GetLastError() : writeError);
                        return false;
                    }
                }
                if (!written)
                {
                    error = L"WriteFile wrote zero bytes";
                    return false;
                }
                done += written;
            }
            return true;
        }

        bool DownloadRange(HINTERNET session, const ParsedUrl& url, const Probe& probe,
            std::uint64_t begin, std::uint64_t end, HANDLE file, unsigned timeout,
            unsigned retries, HANDLE cancelEvent, std::atomic<std::uint64_t>& bytesReceived,
            std::atomic<std::uint64_t>& sessionBytesReceived,
            const std::function<void()>& reportProgress, std::wstring& error)
        {
            const std::uint64_t expected = end - begin + 1;
            for (unsigned attempt = 0; attempt <= retries; ++attempt)
            {
                if (Cancelled(cancelEvent)) { error = L"Cancelled"; return false; }
                HInternet connection(WinHttpConnect(session, url.Host.c_str(), url.Port, 0));
                HInternet request;
                if (!connection || !(request = HInternet(WinHttpOpenRequest(connection.get(), L"GET", url.Path.c_str(),
                    nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, url.Secure ? WINHTTP_FLAG_SECURE : 0))))
                {
                    error = WinErrorText(GetLastError());
                    continue;
                }
                const std::wstring range = L"Range: bytes=" + std::to_wstring(begin) + L"-" + std::to_wstring(end) + L"\r\n";
                if (!WinHttpAddRequestHeaders(request.get(), range.c_str(), static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD) ||
                    (!probe.ValidatorHeader.empty() && !WinHttpAddRequestHeaders(request.get(), probe.ValidatorHeader.c_str(),
                        static_cast<DWORD>(-1), WINHTTP_ADDREQ_FLAG_ADD)))
                {
                    error = WinErrorText(GetLastError());
                    continue;
                }
                if (!WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
                    !WinHttpReceiveResponse(request.get(), nullptr))
                {
                    error = WinErrorText(GetLastError());
                    continue;
                }
                std::uint64_t status = 0;
                QueryNumber(request.get(), WINHTTP_QUERY_STATUS_CODE, status);
                if (status != 206)
                {
                    if (status == 200 || status == 416)
                        error = L"Server stopped honoring byte ranges (HTTP " + std::to_wstring(status) + L")";
                    else
                        error = L"HTTP request returned status " + std::to_wstring(status) +
                        L" for this range";
                    return false;
                }
                const auto cr = QueryHeader(request.get(), WINHTTP_QUERY_CONTENT_RANGE);
                std::uint64_t gotStart = 0, gotEnd = 0, gotTotal = 0;
                if (!ParseContentRange(cr, gotStart, gotEnd, gotTotal) ||
                    gotStart != begin || gotEnd != end || gotTotal != probe.Size)
                {
                    error = L"Content-Range did not match requested range";
                    return false;
                }
                const auto currentEtag = QueryHeader(request.get(), WINHTTP_QUERY_ETAG);
                const auto currentModified = QueryHeader(request.get(), WINHTTP_QUERY_LAST_MODIFIED);
                if ((!probe.ValidatorValue.empty()) &&
                    (probe.ValidatorValue != currentEtag && probe.ValidatorValue != currentModified))
                {
                    error = L"Remote file validator changed during download";
                    return false;
                }

                std::vector<std::byte> body;
                if (expected > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()))
                {
                    error = L"Chunk is too large for this process";
                    return false;
                }
                body.reserve(static_cast<std::size_t>(expected));
                std::uint64_t received = 0;
                if (!ReadResponse(request.get(), body, expected, received, cancelEvent,
                    bytesReceived, sessionBytesReceived, reportProgress, error))
                {
                    bytesReceived.fetch_sub(received, std::memory_order_relaxed);
                    sessionBytesReceived.fetch_sub(received, std::memory_order_relaxed);
                    if (reportProgress) reportProgress();
                    continue;
                }
                if (!WriteAt(file, begin, body.data(), body.size(), error))
                {
                    bytesReceived.fetch_sub(expected, std::memory_order_relaxed);
                    sessionBytesReceived.fetch_sub(expected, std::memory_order_relaxed);
                    if (reportProgress) reportProgress();
                    return false;
                }
                return true;
            }
            return false;
        }

        std::wstring ToHex(const std::vector<UCHAR>& bytes)
        {
            static constexpr wchar_t digits[] = L"0123456789abcdef";
            std::wstring out;
            out.reserve(bytes.size() * 2);
            for (UCHAR b : bytes)
            {
                out.push_back(digits[b >> 4]);
                out.push_back(digits[b & 15]);
            }
            return out;
        }

        bool VerifySha256(const std::filesystem::path& path, const std::wstring& expected, std::wstring& error)
        {
            BCRYPT_ALG_HANDLE algorithm = nullptr;
            BCRYPT_HASH_HANDLE hash = nullptr;
            DWORD objectSize = 0, bytes = 0, hashSize = 0;
            std::vector<UCHAR> object;
            std::vector<UCHAR> digest;
            HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (file == INVALID_HANDLE_VALUE) { error = WinErrorText(GetLastError()); return false; }
            WinHandle fileHandle(file);
            if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
            {
                error = L"BCryptOpenAlgorithmProvider failed";
                return false;
            }
            auto closeAlg = [&] { if (hash) BCryptDestroyHash(hash); if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0); };
            if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize),
                sizeof(objectSize), &bytes, 0) < 0 ||
                BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashSize),
                    sizeof(hashSize), &bytes, 0) < 0)
            {
                closeAlg(); error = L"BCryptGetProperty failed"; return false;
            }
            object.resize(objectSize);
            digest.resize(hashSize);
            if (BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) < 0)
            {
                closeAlg(); error = L"BCryptCreateHash failed"; return false;
            }
            std::array<UCHAR, 64 * 1024> buffer{};
            for (;;)
            {
                DWORD read = 0;
                if (!ReadFile(fileHandle.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
                {
                    closeAlg(); error = WinErrorText(GetLastError()); return false;
                }
                if (!read) break;
                if (BCryptHashData(hash, buffer.data(), read, 0) < 0)
                {
                    closeAlg(); error = L"BCryptHashData failed"; return false;
                }
            }
            if (BCryptFinishHash(hash, digest.data(), hashSize, 0) < 0)
            {
                closeAlg(); error = L"BCryptFinishHash failed"; return false;
            }
            closeAlg();
            std::wstring actual = ToHex(digest);
            std::wstring wanted = expected;
            std::transform(wanted.begin(), wanted.end(), wanted.begin(), towlower);
            if (actual != wanted)
            {
                error = L"SHA-256 mismatch. Actual: " + actual;
                return false;
            }
            return true;
        }

        struct ResumeState
        {
            std::wstring Url;
            std::uint64_t Size = 0;
            std::wstring Validator;
            std::uint64_t ChunkBytes = 0;
            std::vector<bool> Done;
        };

        std::filesystem::path StatePath(const std::filesystem::path& destination)
        {
            return destination.wstring() + L".whrstate";
        }

        bool LoadState(const std::filesystem::path& path, ResumeState& state)
        {
            std::wifstream in(path);
            if (!in) return false;
            std::wstring line;
            if (!std::getline(in, state.Url) || !std::getline(in, line)) return false;
            try { state.Size = std::stoull(line); }
            catch (...) { return false; }
            if (!std::getline(in, state.Validator) || !std::getline(in, line)) return false;
            try { state.ChunkBytes = std::stoull(line); }
            catch (...) { return false; }
            std::wstring done;
            if (!std::getline(in, done)) return false;
            for (wchar_t c : done)
            {
                if (c != L'0' && c != L'1') return false;
                state.Done.push_back(c == L'1');
            }
            return true;
        }

        bool SaveState(const std::filesystem::path& path, const ResumeState& state)
        {
            const auto temp = path.wstring() + L".tmp";
            std::wofstream out(temp, std::ios::trunc);
            if (!out) return false;
            out << state.Url << L'\n' << state.Size << L'\n' << state.Validator << L'\n'
                << state.ChunkBytes << L'\n';
            for (bool done : state.Done) out << (done ? L'1' : L'0');
            out << L'\n';
            out.close();
            if (!out) return false;
            return MoveFileExW(temp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
        }
    }

    DownloadResult Download(const std::wstring& urlString, const std::filesystem::path& destination,
        const DownloadOptions& options, const ProgressCallback& progress, HANDLE cancelEvent)
    {
        DownloadResult result;
        ParsedUrl url;
        if (!ParseUrl(urlString, url))
        {
            result.Message = L"Invalid URL; only HTTP and HTTPS are supported.";
            return result;
        }
        if (!options.Workers || options.Workers > 32 || options.ChunkBytes == 0)
        {
            result.Message = L"Invalid download options.";
            return result;
        }

        HInternet session(WinHttpOpen(L"WinHttpWebDownloader/1.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
        if (!session)
        {
            result.Message = WinErrorText(GetLastError());
            return result;
        }
        const int timeoutMs = static_cast<int>(std::min<std::uint64_t>(
            static_cast<std::uint64_t>(options.TimeoutSeconds) * 1000, INT_MAX));
        if (!WinHttpSetTimeouts(session.get(), timeoutMs, timeoutMs, timeoutMs, timeoutMs))
        {
            result.Message = WinErrorText(GetLastError());
            return result;
        }

        std::error_code ec;
        if (!destination.parent_path().empty())
            std::filesystem::create_directories(destination.parent_path(), ec);
        if (ec)
        {
            result.Message = L"Could not create destination directory.";
            return result;
        }

        Probe probe = ProbeServer(session.get(), url, options.TimeoutSeconds);
        result.HttpStatus = probe.Status;
        const auto statePath = StatePath(destination);

        // Range mode only when a byte-range probe confirms the exact one-byte response.
        if (!probe.RangeSupported || !probe.Size)
        {
            HInternet connection(WinHttpConnect(session.get(), url.Host.c_str(), url.Port, 0));
            if (!connection)
            {
                result.Message = WinErrorText(GetLastError());
                return result;
            }
            HInternet request(WinHttpOpenRequest(connection.get(), L"GET", url.Path.c_str(), nullptr,
                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, url.Secure ? WINHTTP_FLAG_SECURE : 0));
            if (!request || !WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0) || !WinHttpReceiveResponse(request.get(), nullptr))
            {
                result.Message = WinErrorText(GetLastError());
                return result;
            }
            std::uint64_t status = 0;
            QueryNumber(request.get(), WINHTTP_QUERY_STATUS_CODE, status);
            result.HttpStatus = static_cast<unsigned>(status);
            if (status < 200 || status >= 300)
            {
                result.Message = L"HTTP request failed.";
                return result;
            }
            HANDLE raw = CreateFileW(destination.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (raw == INVALID_HANDLE_VALUE)
            {
                result.Message = WinErrorText(GetLastError());
                return result;
            }
            WinHandle file(raw);
            std::uint64_t total = 0;
            QueryNumber(request.get(), WINHTTP_QUERY_CONTENT_LENGTH, total);
            std::uint64_t received = 0;
            std::array<std::byte, 64 * 1024> buffer{};
            while (!Cancelled(cancelEvent))
            {
                DWORD available = 0;
                if (!WinHttpQueryDataAvailable(request.get(), &available))
                {
                    result.Message = WinErrorText(GetLastError()); return result;
                }
                if (!available) break;
                while (available)
                {
                    DWORD read = 0;
                    const DWORD ask = static_cast<DWORD>(std::min<std::size_t>(buffer.size(), available));
                    if (!WinHttpReadData(request.get(), buffer.data(), ask, &read))
                    {
                        result.Message = WinErrorText(GetLastError()); return result;
                    }
                    if (!read) break;
                    DWORD written = 0;
                    if (!WriteFile(file.get(), buffer.data(), read, &written, nullptr) || written != read)
                    {
                        result.Message = WinErrorText(GetLastError()); return result;
                    }
                    received += read;
                    available -= read;
                    if (progress) progress({ received, total, 0, 0 });
                }
            }
            if (Cancelled(cancelEvent))
            {
                result.Message = L"Cancelled";
                return result;
            }
            result.BytesWritten = received;
            result.TotalBytes = total ? total : received;
            if (total && received != total)
            {
                result.Message = L"Single-stream response ended before Content-Length bytes were received.";
                return result;
            }
            if (options.ExpectedSha256)
            {
                if (!VerifySha256(destination, *options.ExpectedSha256, result.Message))
                    return result;
            }
            DeleteFileW(statePath.c_str());
            result.Success = true;
            return result;
        }

        result.TotalBytes = probe.Size;
        const std::uint64_t chunkBytes = options.ChunkBytes;
        const auto chunkCount64 = (probe.Size + chunkBytes - 1) / chunkBytes;
        if (chunkCount64 > std::numeric_limits<unsigned>::max())
        {
            result.Message = L"Too many chunks.";
            return result;
        }
        const unsigned chunkCount = static_cast<unsigned>(chunkCount64);
        ResumeState state;
        bool resumeValid = false;
        if (options.Resume && LoadState(statePath, state) && state.Url == urlString &&
            state.Size == probe.Size && state.Validator == probe.ValidatorValue &&
            state.ChunkBytes == chunkBytes && state.Done.size() == chunkCount)
            resumeValid = true;

        if (!resumeValid)
        {
            state.Url = urlString;
            state.Size = probe.Size;
            state.Validator = probe.ValidatorValue;
            state.ChunkBytes = chunkBytes;
            state.Done.assign(chunkCount, false);
            HANDLE raw = CreateFileW(destination.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (raw == INVALID_HANDLE_VALUE)
            {
                result.Message = WinErrorText(GetLastError());
                return result;
            }
            LARGE_INTEGER size{};
            size.QuadPart = static_cast<LONGLONG>(probe.Size);
            if (!SetFilePointerEx(raw, size, nullptr, FILE_BEGIN) || !SetEndOfFile(raw))
            {
                result.Message = WinErrorText(GetLastError());
                CloseHandle(raw);
                return result;
            }
            CloseHandle(raw);
            if (!SaveState(statePath, state))
            {
                result.Message = L"Could not create resume state file.";
                return result;
            }
        }
        else
        {
            // Open existing file and ensure it is large enough for the saved state.
            HANDLE raw = CreateFileW(destination.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (raw == INVALID_HANDLE_VALUE)
            {
                result.Message = L"Resume state exists but destination file is missing.";
                return result;
            }
            LARGE_INTEGER size{};
            if (!GetFileSizeEx(raw, &size) || static_cast<std::uint64_t>(size.QuadPart) != probe.Size)
            {
                CloseHandle(raw);
                result.Message = L"Resume destination size does not match remote file.";
                return result;
            }
            CloseHandle(raw);
        }

        HANDLE rawFile = CreateFileW(destination.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
        if (rawFile == INVALID_HANDLE_VALUE)
        {
            result.Message = WinErrorText(GetLastError());
            return result;
        }
        WinHandle file(rawFile);

        std::atomic<std::uint64_t> receivedBytes{ 0 };
        std::atomic<std::uint64_t> sessionBytesReceived{ 0 };
        std::atomic<unsigned> completed{ 0 };
        std::atomic<unsigned> retryCount{ 0 };
        std::atomic<unsigned> activeWorkers{ 0 };
        std::mutex stateMutex;
        std::mutex progressMutex;
        std::mutex queueMutex;
        std::condition_variable queueChanged;
        std::deque<unsigned> pendingChunks;
        std::vector<unsigned> attempts(chunkCount, 0);
        std::vector<bool> exhaustedChunks(chunkCount, false);
        std::atomic<bool> failed{ false };
        std::wstring firstError;

        std::uint64_t resumedBytes = 0;
        unsigned resumedChunks = 0;
        for (unsigned i = 0; i < chunkCount; ++i)
        {
            if (state.Done[i])
            {
                ++resumedChunks;
                const std::uint64_t begin = static_cast<std::uint64_t>(i) * chunkBytes;
                const std::uint64_t end = std::min(probe.Size, begin + chunkBytes);
                resumedBytes += end - begin;
                completed.fetch_add(1, std::memory_order_relaxed);
            }
            else
            {
                pendingChunks.push_back(i);
            }
        }
        receivedBytes.store(resumedBytes, std::memory_order_relaxed);

        const auto reportProgress = [&]()
            {
                if (!progress) return;
                std::lock_guard lock(progressMutex);
                DownloadProgress snapshot;
                snapshot.BytesReceived = receivedBytes.load(std::memory_order_relaxed);
                snapshot.TotalBytes = probe.Size;
                snapshot.CompletedChunks = completed.load(std::memory_order_relaxed);
                snapshot.TotalChunks = chunkCount;
                snapshot.SessionBytesReceived = sessionBytesReceived.load(std::memory_order_relaxed);
                snapshot.ResumedBytes = resumedBytes;
                snapshot.ResumedChunks = resumedChunks;
                snapshot.RetryCount = retryCount.load(std::memory_order_relaxed);
                snapshot.ActiveWorkers = activeWorkers.load(std::memory_order_relaxed);
                progress(snapshot);
            };
        reportProgress();

        const auto isFatalRangeError = [](const std::wstring& error)
            {
                return error.find(L"validator changed") != std::wstring::npos ||
                    error.find(L"stopped honoring byte ranges") != std::wstring::npos ||
                    error.find(L"Content-Range did not match") != std::wstring::npos;
            };

        auto worker = [&]()
            {
                for (;;)
                {
                    unsigned index = 0;
                    {
                        std::unique_lock lock(queueMutex);
                        queueChanged.wait(lock, [&]()
                            {
                                return failed.load(std::memory_order_relaxed) ||
                                    Cancelled(cancelEvent) || !pendingChunks.empty() ||
                                    activeWorkers.load(std::memory_order_relaxed) == 0;
                            });

                        if (failed.load(std::memory_order_relaxed) || Cancelled(cancelEvent))
                            return;

                        if (pendingChunks.empty())
                        {
                            if (activeWorkers.load(std::memory_order_relaxed) == 0)
                                return;
                            continue;
                        }

                        index = pendingChunks.front();
                        pendingChunks.pop_front();
                        activeWorkers.fetch_add(1, std::memory_order_relaxed);
                    }
                    reportProgress();

                    bool chunkSucceeded = false;
                    bool fatalError = false;
                    std::wstring error;
                    try
                    {
                        const std::uint64_t begin = static_cast<std::uint64_t>(index) * chunkBytes;
                        const std::uint64_t end = std::min(probe.Size - 1, begin + chunkBytes - 1);

                        // One request per queue attempt. Failed chunks are requeued so
                        // the pool keeps working on the remaining chunks.
                        if (DownloadRange(session.get(), url, probe, begin, end, file.get(),
                            options.TimeoutSeconds, 0, cancelEvent, receivedBytes, sessionBytesReceived,
                            reportProgress, error))
                        {
                            if (!FlushFileBuffers(file.get()))
                            {
                                error = L"Could not flush completed chunk to disk: " + WinErrorText(GetLastError());
                                fatalError = true;
                            }
                            else
                            {
                                std::lock_guard lock(stateMutex);
                                state.Done[index] = true;
                                if (!SaveState(statePath, state))
                                {
                                    state.Done[index] = false;
                                    error = L"Could not persist resume state.";
                                    fatalError = true;
                                }
                                else
                                {
                                    chunkSucceeded = true;
                                }
                            }
                        }
                        else if (error == L"Cancelled")
                        {
                            // Cancellation is handled after the workers have exited.
                        }
                        else if (isFatalRangeError(error))
                        {
                            fatalError = true;
                        }
                    }
                    catch (...)
                    {
                        error = L"Unexpected exception while processing chunk " +
                            std::to_wstring(index) + L".";
                    }

                    {
                        std::lock_guard lock(queueMutex);
                        activeWorkers.fetch_sub(1, std::memory_order_relaxed);

                        if (chunkSucceeded)
                        {
                            completed.fetch_add(1, std::memory_order_relaxed);
                        }
                        else if (fatalError)
                        {
                            if (!failed.exchange(true))
                                firstError = error;
                        }
                        else if (!Cancelled(cancelEvent))
                        {
                            ++attempts[index];
                            retryCount.fetch_add(1, std::memory_order_relaxed);
                            if (attempts[index] <= options.Retries)
                            {
                                pendingChunks.push_back(index);
                            }
                            else
                            {
                                exhaustedChunks[index] = true;
                            }
                        }
                    }

                    reportProgress();
                    queueChanged.notify_all();

                    if (failed.load(std::memory_order_relaxed) || Cancelled(cancelEvent))
                        return;
                }
            };

        const unsigned workers = std::min(options.Workers, chunkCount);
        std::vector<std::thread> threads;
        threads.reserve(workers);
        for (unsigned i = 0; i < workers; ++i)
        {
            threads.emplace_back([&]()
                {
                    // Never allow an exception to escape a thread entry point.
                    // Per-chunk failures are caught above and requeued; this guard
                    // handles only an unexpected failure in the worker loop itself.
                    try
                    {
                        worker();
                    }
                    catch (...)
                    {
                        {
                            std::lock_guard lock(queueMutex);
                            if (!failed.exchange(true))
                                firstError = L"Unexpected worker-thread failure.";
                        }
                        queueChanged.notify_all();
                    }
                });
        }
        for (auto& thread : threads) thread.join();

        result.BytesWritten = receivedBytes.load();
        result.TotalBytes = probe.Size;
        if (Cancelled(cancelEvent))
        {
            result.Message = L"Cancelled; completed chunks have been saved for resume.";
            return result;
        }
        if (failed)
        {
            result.Message = firstError;
            return result;
        }
        const auto exhaustedCount = static_cast<unsigned>(
            std::count(exhaustedChunks.begin(), exhaustedChunks.end(), true));
        if (exhaustedCount != 0)
        {
            result.Message = L"Finished other chunks, but " + std::to_wstring(exhaustedCount) +
                L" chunk(s) exhausted their retry budget. Re-run the same request to resume; " +
                L"completed chunks remain saved.";
            return result;
        }
        if (completed.load() != chunkCount)
        {
            result.Message = L"Download ended with incomplete chunks.";
            return result;
        }
        if (options.ExpectedSha256)
        {
            if (!VerifySha256(destination, *options.ExpectedSha256, result.Message))
                return result;
        }
        DeleteFileW(statePath.c_str());
        result.Success = true;
        result.BytesWritten = probe.Size;
        result.Message = L"Downloaded using parallel HTTP range requests.";
        return result;
    }
}
