#pragma once
#include "MemScanner.h"
#include "ProcessEngine.h"

// ─── Scan Engine ──────────────────────────────────────────────────────────────
// Multi-threaded first/next scan, AoB, string, pointer scanner
class ScanEngine {
public:
    explicit ScanEngine(ProcessEngine& pe);
    ~ScanEngine();

    // First scan – populates session.results
    ScanStats firstScan(ScanSession& session, const ScanOptions& opts,
                        const std::string& valueStr,
                        std::function<void(float)> progressCb = nullptr);

    // Next scan – filters session.results
    ScanStats nextScan(ScanSession& session, const ScanOptions& opts,
                       const std::string& valueStr,
                       std::function<void(float)> progressCb = nullptr);

    // Refresh current values in result list
    void refreshResults(ScanSession& session, const ScanOptions& opts);

    // AoB scan (standalone, writes to session)
    ScanStats aobScan(ScanSession& session, const std::string& pattern,
                      ProtectionFilter pf, RegionTypeFilter rf,
                      std::function<void(float)> progressCb = nullptr);

    // String scan
    ScanStats stringScan(ScanSession& session, const std::string& pattern,
                         bool caseSensitive, bool isWide,
                         ProtectionFilter pf, RegionTypeFilter rf,
                         std::function<void(float)> progressCb = nullptr);

    // Pointer scanner – find chains leading to address
    void pointerScan(uintptr_t targetAddr, int maxDepth, uintptr_t maxOffset,
                     std::vector<PointerChain>& outChains,
                     std::function<void(float)> progressCb = nullptr);

    // Cancel ongoing scan
    void cancel() { cancelFlag_ = true; }
    bool isScanning() const { return scanning_; }

    // Parse AoB pattern string "AA BB ?? CC" → bytes + mask
    static bool parseAoB(const std::string& pattern,
                         std::vector<uint8_t>& bytes,
                         std::vector<bool>& mask);

    // Format value as string
    static std::string valueToString(const ScanResult& r);
    static std::string formatAddress(uintptr_t addr, bool is64);

private:
    ProcessEngine& pe_;
    std::atomic<bool> cancelFlag_{ false };
    std::atomic<bool> scanning_{ false };

    // Decode a value from raw bytes according to type
    static uint64_t decodeValue(const uint8_t* data, ValueType t);
    static void     encodeValue(uint64_t v, ValueType t, uint8_t* out);

    // Parse value string to raw uint64
    static bool     parseValueStr(const std::string& s, ValueType t, uint64_t& outRaw, uint64_t& outRaw2);

    // Condition predicate
    static bool     evaluateCondition(uint64_t current, uint64_t previous,
                                      uint64_t target, uint64_t target2,
                                      ScanCondition cond, ValueType type,
                                      float fEps, double dEps);

    // Scan a single chunk; returns matching offsets
    void scanChunk(const uint8_t* data, size_t dataLen, uintptr_t baseAddr,
                   ValueType type, ScanCondition cond,
                   uint64_t target, uint64_t target2,
                   const std::unordered_map<uintptr_t,uint64_t>& prevMap,
                   size_t alignment, float fEps, double dEps,
                   std::vector<ScanResult>& out, size_t maxResults);

    // Thread pool
    struct WorkerPool {
        std::vector<std::thread> threads;
        std::queue<std::function<void()>> queue;
        std::mutex mtx;
        std::condition_variable cv;
        std::atomic<bool> stop{ false };
        std::atomic<int>  pending{ 0 };

        WorkerPool(size_t n);
        ~WorkerPool();
        void enqueue(std::function<void()> fn);
        void waitAll();
    };
};
