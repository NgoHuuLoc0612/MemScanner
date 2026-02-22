#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <optional>
#include <variant>
#include <queue>
#include <condition_variable>
#include <future>
#include <bitset>
#include <filesystem>

// ─── Value Types ─────────────────────────────────────────────────────────────
enum class ValueType : uint8_t {
    Int8 = 0, UInt8, Int16, UInt16, Int32, UInt32,
    Int64, UInt64, Float, Double, Vec2, Vec3, Vec4,
    AoB,        // Array of Bytes with wildcards
    String,     // UTF-8
    WString,    // UTF-16
    Custom,     // user-defined struct
    COUNT
};

static constexpr const char* ValueTypeNames[] = {
    "Int8","UInt8","Int16","UInt16","Int32","UInt32",
    "Int64","UInt64","Float","Double","Vec2(f)","Vec3(f)","Vec4(f)",
    "AoB","String","WString","Custom"
};

static constexpr size_t ValueTypeSizes[] = {
    1,1,2,2,4,4,8,8,4,8,8,12,16,0,0,0,0
};

// ─── Scan Condition ───────────────────────────────────────────────────────────
enum class ScanCondition : uint8_t {
    ExactValue = 0,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
    Between,
    // Delta-based (require previous scan)
    IncreasedBy,
    DecreasedBy,
    Increased,
    Decreased,
    Changed,
    Unchanged,
    // Bitwise
    BitwiseAND,
    BitwiseOR,
    COUNT
};

static constexpr const char* ScanConditionNames[] = {
    "Exact Value","Not Equal","Greater Than","Less Than",
    "Greater Or Equal","Less Or Equal","Between",
    "Increased By","Decreased By","Increased","Decreased",
    "Changed","Unchanged","Bitwise AND","Bitwise OR"
};

// ─── Memory Protection Flags ──────────────────────────────────────────────────
enum class ProtectionFilter : uint32_t {
    None         = 0,
    Readable     = 1 << 0,
    Writable     = 1 << 1,
    Executable   = 1 << 2,
    CopyOnWrite  = 1 << 3,
    All          = 0xFFFFFFFF
};
inline ProtectionFilter operator|(ProtectionFilter a, ProtectionFilter b) {
    return static_cast<ProtectionFilter>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline bool operator&(ProtectionFilter a, ProtectionFilter b) {
    return (static_cast<uint32_t>(a) & static_cast<uint32_t>(b)) != 0;
}

// ─── Region Type Filter ───────────────────────────────────────────────────────
enum class RegionTypeFilter : uint32_t {
    None     = 0,
    Private  = 1 << 0,
    Mapped   = 1 << 1,
    Image    = 1 << 2,
    All      = 0xFFFFFFFF
};
inline RegionTypeFilter operator|(RegionTypeFilter a, RegionTypeFilter b) {
    return static_cast<RegionTypeFilter>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline bool operator&(RegionTypeFilter a, RegionTypeFilter b) {
    return (static_cast<uint32_t>(a) & static_cast<uint32_t>(b)) != 0;
}

// ─── Scan Options ─────────────────────────────────────────────────────────────
struct ScanOptions {
    ValueType           type            = ValueType::Int32;
    ScanCondition       condition       = ScanCondition::ExactValue;
    ProtectionFilter    protFilter      = ProtectionFilter::Readable | ProtectionFilter::Writable;
    RegionTypeFilter    regionFilter    = RegionTypeFilter::Private | RegionTypeFilter::Mapped;
    bool                scanMapped      = true;
    bool                scanImage       = false;
    bool                writable        = true;
    bool                executable      = false;
    bool                aligned         = true;
    size_t              alignment       = 4;
    float               floatEpsilon    = 0.0001f;
    double              doubleEpsilon   = 0.000001;
    size_t              maxResults      = 10'000'000;
    size_t              chunkSize       = 4 * 1024 * 1024; // 4MB read chunks
    size_t              threadCount     = 0; // 0 = auto
    bool                pauseTarget     = false;
    // AoB
    std::vector<uint8_t> aobPattern;
    std::vector<bool>    aobMask;
    // String
    std::string          strPattern;
    bool                 strCaseSensitive = true;
    bool                 strUnicode       = false;
    // Custom struct
    size_t               customSize      = 0;
    std::vector<uint8_t> customData;
};

// ─── Memory Region ────────────────────────────────────────────────────────────
struct MemRegion {
    uintptr_t   base;
    size_t      size;
    DWORD       protect;
    DWORD       state;
    DWORD       type;
    std::string moduleName; // if Image
    bool        isStack     = false;
    bool        isHeap      = false;

    bool isReadable()   const;
    bool isWritable()   const;
    bool isExecutable() const;
    std::string protectString() const;
    std::string typeString()    const;
};

// ─── Scan Result Entry ────────────────────────────────────────────────────────
struct ScanResult {
    uintptr_t   address;
    ValueType   type;
    uint64_t    rawPrevious; // raw bytes up to 8
    uint64_t    rawCurrent;  // raw bytes up to 8
    // For extended types
    std::vector<uint8_t> extData;
    std::string regionModule;

    template<typename T> T prevAs() const { T v; memcpy(&v, &rawPrevious, sizeof(T)); return v; }
    template<typename T> T currAs() const { T v; memcpy(&v, &rawCurrent,  sizeof(T)); return v; }
};

// ─── Pointer Chain ────────────────────────────────────────────────────────────
struct PointerChain {
    std::string     name;
    std::string     moduleName;
    uintptr_t       moduleBase   = 0;
    uintptr_t       baseOffset   = 0;
    std::vector<uintptr_t> offsets;
    ValueType       type         = ValueType::Int32;
    bool            frozen       = false;
    uint64_t        frozenValue  = 0;
    bool            active       = true;
};

// ─── Breakpoint ───────────────────────────────────────────────────────────────
enum class BreakpointType : uint8_t { Execute=0, Write, ReadWrite };
struct Breakpoint {
    std::string     name;
    uintptr_t       address;
    BreakpointType  bpType;
    size_t          size; // 1,2,4
    bool            enabled;
    uint64_t        hitCount;
    std::chrono::steady_clock::time_point lastHit;
};

// ─── Memory Patch ─────────────────────────────────────────────────────────────
struct MemPatch {
    std::string         name;
    uintptr_t           address;
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> patchedBytes;
    bool                applied = false;
    bool                active  = true;
};

// ─── Watch Entry ─────────────────────────────────────────────────────────────
struct WatchEntry {
    std::string     label;
    uintptr_t       address;
    ValueType       type;
    bool            frozen      = false;
    uint64_t        frozenValue = 0;
    bool            highlight   = false;
    uint32_t        color       = 0xFFFFFFFF;
    // history ring buffer
    static constexpr size_t HIST_CAP = 256;
    float           history[256] = {};
    int             histHead = 0;
    int             histCount = 0;
    void pushHistory(float v) {
        history[histHead] = v;
        histHead = (histHead + 1) % HIST_CAP;
        if (histCount < (int)HIST_CAP) ++histCount;
    }
};

// ─── Process Info ─────────────────────────────────────────────────────────────
struct ModuleInfo {
    std::string  name;
    uintptr_t    base;
    size_t       size;
    std::string  path;
    bool         is64bit;
};

struct ProcessInfo {
    DWORD           pid;
    std::string     name;
    std::string     path;
    HANDLE          handle      = INVALID_HANDLE_VALUE;
    bool            is64bit     = false;
    std::vector<ModuleInfo> modules;
    uint64_t        workingSet  = 0;
    uint64_t        peakWorkingSet = 0;
    DWORD           numThreads  = 0;
    double          cpuUsage    = 0.0;
};

// ─── Scan Session ─────────────────────────────────────────────────────────────
struct ScanSession {
    std::string             name;
    ValueType               type;
    std::vector<ScanResult> results;
    size_t                  scanCount   = 0;
    std::chrono::steady_clock::time_point lastScan;
    bool                    hasFirst    = false;
};

// ─── Disassembly Entry ────────────────────────────────────────────────────────
struct DisasmEntry {
    uintptr_t   address;
    uint8_t     length;
    std::string bytes;
    std::string mnemonic;
    std::string operands;
    bool        isJump      = false;
    bool        isCall      = false;
    bool        isRet       = false;
};

// ─── Heap Block ───────────────────────────────────────────────────────────────
struct HeapBlock {
    uintptr_t address;
    size_t    size;
    DWORD     flags;
    bool      isBusy;
};

// ─── Scanner stats ────────────────────────────────────────────────────────────
struct ScanStats {
    size_t  regionsScanned    = 0;
    size_t  bytesScanned      = 0;
    size_t  resultsFound      = 0;
    double  elapsedMs         = 0.0;
    double  throughputMBs     = 0.0;
    bool    wasTruncated      = false;
};

// ─── Thread-pool task ─────────────────────────────────────────────────────────
struct ScanTask {
    uintptr_t           base;
    std::vector<uint8_t> data;
    size_t              startIdx;
};