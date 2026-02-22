#include "ScanEngine.h"
#include <cmath>
#include <cctype>
#include <stdexcept>

// ─── WorkerPool ───────────────────────────────────────────────────────────────
ScanEngine::WorkerPool::WorkerPool(size_t n) {
    for (size_t i = 0; i < n; ++i) {
        threads.emplace_back([this]{
            while (true) {
                std::function<void()> fn;
                {
                    std::unique_lock<std::mutex> lk(mtx);
                    cv.wait(lk, [this]{ return stop || !queue.empty(); });
                    if (stop && queue.empty()) return;
                    fn = std::move(queue.front());
                    queue.pop();
                }
                fn();
                --pending;
                cv.notify_all();
            }
        });
    }
}
ScanEngine::WorkerPool::~WorkerPool() {
    { std::unique_lock<std::mutex> lk(mtx); stop = true; }
    cv.notify_all();
    for (auto& t : threads) if (t.joinable()) t.join();
}
void ScanEngine::WorkerPool::enqueue(std::function<void()> fn) {
    ++pending;
    { std::unique_lock<std::mutex> lk(mtx); queue.push(std::move(fn)); }
    cv.notify_one();
}
void ScanEngine::WorkerPool::waitAll() {
    std::unique_lock<std::mutex> lk(mtx);
    cv.wait(lk, [this]{ return pending == 0 && queue.empty(); });
}

// ─── ScanEngine ───────────────────────────────────────────────────────────────
ScanEngine::ScanEngine(ProcessEngine& pe) : pe_(pe) {}
ScanEngine::~ScanEngine() { cancel(); }

// ─── AoB Parse ───────────────────────────────────────────────────────────────
bool ScanEngine::parseAoB(const std::string& pattern, std::vector<uint8_t>& bytes, std::vector<bool>& mask) {
    bytes.clear(); mask.clear();
    std::istringstream ss(pattern);
    std::string token;
    while (ss >> token) {
        if (token == "?" || token == "??") {
            bytes.push_back(0);
            mask.push_back(false);
        } else {
            if (token.size() != 2) return false;
            char* end;
            uint8_t b = (uint8_t)std::strtoul(token.c_str(), &end, 16);
            if (end != token.c_str() + 2) return false;
            bytes.push_back(b);
            mask.push_back(true);
        }
    }
    return !bytes.empty();
}

// ─── Decode / Encode ─────────────────────────────────────────────────────────
uint64_t ScanEngine::decodeValue(const uint8_t* d, ValueType t) {
    uint64_t v = 0;
    switch (t) {
        case ValueType::Int8:  { int8_t  x; memcpy(&x,d,1); v = (uint64_t)(int64_t)x; break; }
        case ValueType::UInt8: { uint8_t x; memcpy(&x,d,1); v = x; break; }
        case ValueType::Int16: { int16_t x; memcpy(&x,d,2); v = (uint64_t)(int64_t)x; break; }
        case ValueType::UInt16:{ uint16_t x; memcpy(&x,d,2); v = x; break; }
        case ValueType::Int32: { int32_t x; memcpy(&x,d,4); v = (uint64_t)(int64_t)x; break; }
        case ValueType::UInt32:{ uint32_t x; memcpy(&x,d,4); v = x; break; }
        case ValueType::Int64: { int64_t  x; memcpy(&x,d,8); v = (uint64_t)x; break; }
        case ValueType::UInt64:{ memcpy(&v,d,8); break; }
        case ValueType::Float: { float  x; memcpy(&x,d,4); memcpy(&v,&x,4); break; }
        case ValueType::Double:{ double x; memcpy(&x,d,8); memcpy(&v,&x,8); break; }
        default: break;
    }
    return v;
}

bool ScanEngine::parseValueStr(const std::string& s, ValueType t, uint64_t& out, uint64_t& out2) {
    out = out2 = 0;
    try {
        if (t == ValueType::Float) {
            float f = std::stof(s); memcpy(&out, &f, 4); return true;
        }
        if (t == ValueType::Double) {
            double d = std::stod(s); memcpy(&out, &d, 8); return true;
        }
        if (t == ValueType::Int8 || t == ValueType::Int16 ||
            t == ValueType::Int32 || t == ValueType::Int64) {
            int64_t v = std::stoll(s); out = (uint64_t)v; return true;
        }
        uint64_t v = std::stoull(s); out = v; return true;
    } catch (...) { return false; }
}

bool ScanEngine::evaluateCondition(uint64_t cur, uint64_t prev,
                                    uint64_t tgt, uint64_t tgt2,
                                    ScanCondition cond, ValueType type,
                                    float fEps, double dEps) {
    auto flt = [](uint64_t v){ float f; memcpy(&f,&v,4); return f; };
    auto dbl = [](uint64_t v){ double d; memcpy(&d,&v,8); return d; };
    bool isF = (type == ValueType::Float);
    bool isD = (type == ValueType::Double);
    bool isSigned = (type==ValueType::Int8||type==ValueType::Int16||
                     type==ValueType::Int32||type==ValueType::Int64);

    switch (cond) {
        case ScanCondition::ExactValue:
            if (isF) return std::fabs(flt(cur)-flt(tgt)) <= fEps;
            if (isD) return std::fabs(dbl(cur)-dbl(tgt)) <= dEps;
            return cur == tgt;
        case ScanCondition::NotEqual:
            if (isF) return std::fabs(flt(cur)-flt(tgt)) > fEps;
            if (isD) return std::fabs(dbl(cur)-dbl(tgt)) > dEps;
            return cur != tgt;
        case ScanCondition::GreaterThan:
            if (isF) return flt(cur) > flt(tgt);
            if (isD) return dbl(cur) > dbl(tgt);
            if (isSigned) return (int64_t)cur > (int64_t)tgt;
            return cur > tgt;
        case ScanCondition::LessThan:
            if (isF) return flt(cur) < flt(tgt);
            if (isD) return dbl(cur) < dbl(tgt);
            if (isSigned) return (int64_t)cur < (int64_t)tgt;
            return cur < tgt;
        case ScanCondition::GreaterOrEqual:
            if (isF) return flt(cur) >= flt(tgt)-fEps;
            if (isD) return dbl(cur) >= dbl(tgt)-dEps;
            if (isSigned) return (int64_t)cur >= (int64_t)tgt;
            return cur >= tgt;
        case ScanCondition::LessOrEqual:
            if (isF) return flt(cur) <= flt(tgt)+fEps;
            if (isD) return dbl(cur) <= dbl(tgt)+dEps;
            if (isSigned) return (int64_t)cur <= (int64_t)tgt;
            return cur <= tgt;
        case ScanCondition::Between:
            if (isF) return flt(cur) >= flt(tgt) && flt(cur) <= flt(tgt2);
            if (isD) return dbl(cur) >= dbl(tgt) && dbl(cur) <= dbl(tgt2);
            if (isSigned) return (int64_t)cur>=(int64_t)tgt && (int64_t)cur<=(int64_t)tgt2;
            return cur >= tgt && cur <= tgt2;
        case ScanCondition::Changed:    return cur != prev;
        case ScanCondition::Unchanged:  return cur == prev;
        case ScanCondition::Increased:
            if (isF) return flt(cur) > flt(prev);
            if (isD) return dbl(cur) > dbl(prev);
            if (isSigned) return (int64_t)cur > (int64_t)prev;
            return cur > prev;
        case ScanCondition::Decreased:
            if (isF) return flt(cur) < flt(prev);
            if (isD) return dbl(cur) < dbl(prev);
            if (isSigned) return (int64_t)cur < (int64_t)prev;
            return cur < prev;
        case ScanCondition::IncreasedBy:
            if (isF) return std::fabs((flt(cur)-flt(prev))-flt(tgt)) <= fEps;
            if (isD) return std::fabs((dbl(cur)-dbl(prev))-dbl(tgt)) <= dEps;
            if (isSigned) return (int64_t)cur - (int64_t)prev == (int64_t)tgt;
            return cur - prev == tgt;
        case ScanCondition::DecreasedBy:
            if (isF) return std::fabs((flt(prev)-flt(cur))-flt(tgt)) <= fEps;
            if (isD) return std::fabs((dbl(prev)-dbl(cur))-dbl(tgt)) <= dEps;
            if (isSigned) return (int64_t)prev - (int64_t)cur == (int64_t)tgt;
            return prev - cur == tgt;
        case ScanCondition::BitwiseAND: return (cur & tgt) == tgt;
        case ScanCondition::BitwiseOR:  return (cur | tgt) != 0;
        default: return false;
    }
}

// ─── Scan chunk ───────────────────────────────────────────────────────────────
void ScanEngine::scanChunk(const uint8_t* data, size_t dataLen, uintptr_t baseAddr,
                            ValueType type, ScanCondition cond,
                            uint64_t target, uint64_t target2,
                            const std::unordered_map<uintptr_t,uint64_t>& prevMap,
                            size_t alignment, float fEps, double dEps,
                            std::vector<ScanResult>& out, size_t maxResults) {
    size_t typeSize = ValueTypeSizes[(int)type];
    if (typeSize == 0 || typeSize > dataLen) return;
    bool needPrev = (cond == ScanCondition::Changed || cond == ScanCondition::Unchanged ||
                     cond == ScanCondition::Increased || cond == ScanCondition::Decreased ||
                     cond == ScanCondition::IncreasedBy || cond == ScanCondition::DecreasedBy);

    for (size_t off = 0; off + typeSize <= dataLen; off += alignment) {
        if (out.size() >= maxResults) break;
        uintptr_t addr = baseAddr + off;
        uint64_t cur = decodeValue(data + off, type);
        uint64_t prev = 0;
        if (needPrev) {
            auto it = prevMap.find(addr);
            if (it == prevMap.end()) continue;
            prev = it->second;
        }
        if (evaluateCondition(cur, prev, target, target2, cond, type, fEps, dEps)) {
            ScanResult r;
            r.address     = addr;
            r.type        = type;
            r.rawCurrent  = cur;
            r.rawPrevious = prev;
            out.push_back(r);
        }
    }
}

// ─── First Scan ───────────────────────────────────────────────────────────────
ScanStats ScanEngine::firstScan(ScanSession& session, const ScanOptions& opts,
                                 const std::string& valueStr,
                                 std::function<void(float)> progressCb) {
    ScanStats stats;
    cancelFlag_ = false;
    scanning_   = true;

    uint64_t target = 0, target2 = 0;
    bool needTarget = !(opts.condition == ScanCondition::Changed ||
                        opts.condition == ScanCondition::Unchanged ||
                        opts.condition == ScanCondition::Increased ||
                        opts.condition == ScanCondition::Decreased);
    if (needTarget && !parseValueStr(valueStr, opts.type, target, target2)) {
        scanning_ = false;
        return stats;
    }
    // Guard: must be attached
    if (!pe_.attached()) { scanning_ = false; return stats; }

    // Handle "between" second value from "X..Y"
    if (opts.condition == ScanCondition::Between) {
        size_t dotPos = valueStr.find("..");
        if (dotPos != std::string::npos) {
            parseValueStr(valueStr.substr(dotPos + 2), opts.type, target2, target2);
        }
    }

    auto regions = pe_.queryRegions(opts.protFilter, opts.regionFilter);
    size_t totalBytes = 0;
    for (auto& r : regions) totalBytes += r.size;

    size_t threadCount = opts.threadCount > 0 ? opts.threadCount :
                         std::max(1u, std::thread::hardware_concurrency());
    WorkerPool pool(threadCount);

    std::vector<std::vector<ScanResult>> partials(regions.size());
    std::mutex statsMtx;
    std::atomic<size_t> processed{ 0 };
    auto t0 = std::chrono::high_resolution_clock::now();

    if (opts.pauseTarget) pe_.suspend();

    for (size_t ri = 0; ri < regions.size() && !cancelFlag_; ++ri) {
        const MemRegion& reg = regions[ri];
        pool.enqueue([&, ri, reg] {
            if (cancelFlag_) return;
            std::vector<uint8_t> buf;
            buf.resize(reg.size);
            SIZE_T rd = 0;
            if (!ReadProcessMemory(pe_.handle(), (LPCVOID)reg.base, buf.data(), reg.size, &rd) || rd == 0) {
                processed += reg.size;
                if (progressCb && totalBytes > 0) {
                    std::lock_guard<std::mutex> lk(statsMtx);
                    progressCb((float)(size_t)processed / (float)totalBytes);
                }
                return;
            }
            buf.resize(rd);

            scanChunk(buf.data(), rd, reg.base, opts.type, opts.condition,
                      target, target2, {}, opts.alignment,
                      opts.floatEpsilon, opts.doubleEpsilon,
                      partials[ri], opts.maxResults);

            {
                std::lock_guard<std::mutex> lk(statsMtx);
                stats.bytesScanned += rd;
                ++stats.regionsScanned;
                processed += reg.size;
                if (progressCb && totalBytes > 0)
                    progressCb((float)(size_t)processed / (float)totalBytes);
            }
        });
    }
    pool.waitAll();

    if (opts.pauseTarget) pe_.resume();

    session.results.clear();
    for (auto& p : partials) {
        for (auto& r : p) {
            if (session.results.size() >= opts.maxResults) { stats.wasTruncated = true; break; }
            session.results.push_back(r);
        }
    }
    session.type     = opts.type;
    session.hasFirst = true;
    ++session.scanCount;
    session.lastScan = std::chrono::steady_clock::now();

    auto t1 = std::chrono::high_resolution_clock::now();
    stats.elapsedMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    if (stats.elapsedMs > 0)
        stats.throughputMBs = (stats.bytesScanned / 1024.0 / 1024.0) / (stats.elapsedMs / 1000.0);
    stats.resultsFound = session.results.size();

    scanning_ = false;
    return stats;
}

// ─── Next Scan ────────────────────────────────────────────────────────────────
ScanStats ScanEngine::nextScan(ScanSession& session, const ScanOptions& opts,
                                const std::string& valueStr,
                                std::function<void(float)> progressCb) {
    ScanStats stats;
    if (!session.hasFirst) return firstScan(session, opts, valueStr, progressCb);

    cancelFlag_ = false;
    scanning_   = true;

    uint64_t target = 0, target2 = 0;
    bool needTarget = !(opts.condition == ScanCondition::Changed ||
                        opts.condition == ScanCondition::Unchanged ||
                        opts.condition == ScanCondition::Increased ||
                        opts.condition == ScanCondition::Decreased);
    if (needTarget && !parseValueStr(valueStr, opts.type, target, target2)) {
        scanning_ = false;
        return stats;
    }
    if (opts.condition == ScanCondition::Between) {
        size_t dotPos = valueStr.find("..");
        if (dotPos != std::string::npos)
            parseValueStr(valueStr.substr(dotPos+2), opts.type, target2, target2);
    }

    // Build previous map
    std::unordered_map<uintptr_t, uint64_t> prevMap;
    prevMap.reserve(session.results.size());
    for (auto& r : session.results)
        prevMap[r.address] = r.rawCurrent;

    if (opts.pauseTarget) pe_.suspend();

    auto t0 = std::chrono::high_resolution_clock::now();

    // Group results by page to batch reads
    std::vector<ScanResult> newResults;
    newResults.reserve(session.results.size() / 4);

    // Process in blocks grouped by proximity
    size_t i = 0;
    size_t total = session.results.size();
    static const size_t BATCH = 4096;
    std::vector<uint8_t> buf;

    while (i < total && !cancelFlag_) {
        uintptr_t batchBase = session.results[i].address & ~(uintptr_t)(opts.chunkSize - 1);
        uintptr_t batchEnd  = batchBase + opts.chunkSize;
        buf.resize(opts.chunkSize);
        SIZE_T rd = 0;
        bool readOk = ReadProcessMemory(pe_.handle(), (LPCVOID)batchBase, buf.data(), opts.chunkSize, &rd);
        size_t j = i;
        while (j < total && session.results[j].address < batchEnd) {
            if (readOk && session.results[j].address >= batchBase) {
                size_t off = session.results[j].address - batchBase;
                size_t typeSize = ValueTypeSizes[(int)opts.type];
                if (off + typeSize <= rd) {
                    uint64_t cur = decodeValue(buf.data() + off, opts.type);
                    uint64_t prev = prevMap.count(session.results[j].address) ?
                                    prevMap[session.results[j].address] : 0;
                    if (evaluateCondition(cur, prev, target, target2,
                                          opts.condition, opts.type,
                                          opts.floatEpsilon, opts.doubleEpsilon)) {
                        ScanResult r = session.results[j];
                        r.rawPrevious = prev;
                        r.rawCurrent  = cur;
                        newResults.push_back(r);
                    }
                    ++stats.bytesScanned;
                }
            }
            ++j;
        }
        ++stats.regionsScanned;
        i = j;
        if (progressCb) progressCb((float)i / (float)total);
    }

    if (opts.pauseTarget) pe_.resume();

    session.results = std::move(newResults);
    ++session.scanCount;
    session.lastScan = std::chrono::steady_clock::now();

    auto t1 = std::chrono::high_resolution_clock::now();
    stats.elapsedMs    = std::chrono::duration<double, std::milli>(t1 - t0).count();
    stats.resultsFound = session.results.size();
    if (stats.elapsedMs > 0)
        stats.throughputMBs = (stats.bytesScanned / 1024.0 / 1024.0) / (stats.elapsedMs / 1000.0);

    scanning_ = false;
    return stats;
}

// ─── Refresh ─────────────────────────────────────────────────────────────────
void ScanEngine::refreshResults(ScanSession& session, const ScanOptions& opts) {
    size_t typeSize = ValueTypeSizes[(int)opts.type];
    if (typeSize == 0) return;
    for (auto& r : session.results) {
        r.rawPrevious = r.rawCurrent;
        uint64_t cur = 0;
        if (pe_.readBytes(r.address, &cur, typeSize))
            r.rawCurrent = decodeValue((uint8_t*)&cur, opts.type);
    }
}

// ─── AoB Scan ─────────────────────────────────────────────────────────────────
ScanStats ScanEngine::aobScan(ScanSession& session, const std::string& pattern,
                               ProtectionFilter pf, RegionTypeFilter rf,
                               std::function<void(float)> progressCb) {
    ScanStats stats;
    std::vector<uint8_t> patBytes;
    std::vector<bool> patMask;
    if (!parseAoB(pattern, patBytes, patMask)) return stats;
    size_t patLen = patBytes.size();

    cancelFlag_ = false;
    scanning_   = true;

    auto regions = pe_.queryRegions(pf, rf);
    size_t totalBytes = 0;
    for (auto& r : regions) totalBytes += r.size;

    std::atomic<size_t> processed{ 0 };
    std::mutex resMtx;
    std::vector<ScanResult> allResults;
    auto t0 = std::chrono::high_resolution_clock::now();

    size_t threadCount = std::max(1u, std::thread::hardware_concurrency());
    WorkerPool pool(threadCount);

    for (auto& reg : regions) {
        pool.enqueue([&, reg] {
            if (cancelFlag_) return;
            std::vector<uint8_t> buf(reg.size);
            SIZE_T rd = 0;
            if (!ReadProcessMemory(pe_.handle(), (LPCVOID)reg.base, buf.data(), reg.size, &rd) || rd < patLen)
                return;

            std::vector<ScanResult> local;
            for (size_t i = 0; i + patLen <= rd; ++i) {
                bool match = true;
                for (size_t j = 0; j < patLen; ++j) {
                    if (patMask[j] && buf[i+j] != patBytes[j]) { match = false; break; }
                }
                if (match) {
                    ScanResult r;
                    r.address = reg.base + i;
                    r.type    = ValueType::AoB;
                    r.extData.assign(buf.data()+i, buf.data()+i+patLen);
                    local.push_back(r);
                }
            }
            if (!local.empty()) {
                std::lock_guard<std::mutex> lk(resMtx);
                for (auto& x : local) allResults.push_back(x);
            }
            {
                std::lock_guard<std::mutex> lk(resMtx);
                stats.bytesScanned += rd;
                ++stats.regionsScanned;
            }
            processed += reg.size;
            if (progressCb) progressCb((float)processed / (float)totalBytes);
        });
    }
    pool.waitAll();

    session.results = std::move(allResults);
    session.type    = ValueType::AoB;
    session.hasFirst = true;
    ++session.scanCount;

    auto t1 = std::chrono::high_resolution_clock::now();
    stats.elapsedMs    = std::chrono::duration<double, std::milli>(t1 - t0).count();
    stats.resultsFound = session.results.size();
    if (stats.elapsedMs > 0)
        stats.throughputMBs = (stats.bytesScanned/1024.0/1024.0) / (stats.elapsedMs/1000.0);

    scanning_ = false;
    return stats;
}

// ─── String Scan ─────────────────────────────────────────────────────────────
ScanStats ScanEngine::stringScan(ScanSession& session, const std::string& pattern,
                                  bool caseSensitive, bool isWide,
                                  ProtectionFilter pf, RegionTypeFilter rf,
                                  std::function<void(float)> progressCb) {
    ScanStats stats;
    if (pattern.empty()) return stats;
    cancelFlag_ = false;
    scanning_   = true;

    std::wstring wpat = ProcessEngine::utf8ToWide(pattern);
    std::wstring wpatlower = wpat;
    std::transform(wpatlower.begin(), wpatlower.end(), wpatlower.begin(), ::tolower);
    std::string spat = pattern;
    std::string spatlower = pattern;
    std::transform(spatlower.begin(), spatlower.end(), spatlower.begin(), ::tolower);

    auto regions = pe_.queryRegions(pf, rf);
    size_t totalBytes = 0;
    for (auto& r : regions) totalBytes += r.size;

    std::mutex resMtx;
    std::vector<ScanResult> allResults;
    std::atomic<size_t> processed{ 0 };
    auto t0 = std::chrono::high_resolution_clock::now();

    size_t threadCount = std::max(1u, std::thread::hardware_concurrency());
    WorkerPool pool(threadCount);

    for (auto& reg : regions) {
        pool.enqueue([&, reg] {
            if (cancelFlag_) return;
            std::vector<uint8_t> buf(reg.size + 4, 0);
            SIZE_T rd = 0;
            if (!ReadProcessMemory(pe_.handle(), (LPCVOID)reg.base, buf.data(), reg.size, &rd)) return;

            std::vector<ScanResult> local;
            if (!isWide) {
                // UTF-8 search
                for (size_t i = 0; i + spat.size() <= rd; ++i) {
                    bool match = true;
                    if (caseSensitive) {
                        match = memcmp(buf.data()+i, spat.c_str(), spat.size()) == 0;
                    } else {
                        for (size_t j = 0; j < spat.size(); ++j) {
                            if (tolower(buf[i+j]) != (unsigned char)spatlower[j]) { match = false; break; }
                        }
                    }
                    if (match) {
                        ScanResult r;
                        r.address = reg.base + i;
                        r.type    = ValueType::String;
                        r.extData.assign(buf.data()+i, buf.data()+i+spat.size());
                        local.push_back(r);
                    }
                }
            } else {
                // UTF-16 search
                size_t wsz = wpat.size() * 2;
                for (size_t i = 0; i + wsz <= rd; i += 2) {
                    bool match = true;
                    if (caseSensitive) {
                        match = memcmp(buf.data()+i, wpat.c_str(), wsz) == 0;
                    } else {
                        for (size_t j = 0; j < wpat.size(); ++j) {
                            wchar_t c; memcpy(&c, buf.data()+i+j*2, 2);
                            if (towlower(c) != wpatlower[j]) { match = false; break; }
                        }
                    }
                    if (match) {
                        ScanResult r;
                        r.address = reg.base + i;
                        r.type    = ValueType::WString;
                        r.extData.assign(buf.data()+i, buf.data()+i+wsz);
                        local.push_back(r);
                    }
                }
            }
            if (!local.empty()) {
                std::lock_guard<std::mutex> lk(resMtx);
                for (auto& x : local) allResults.push_back(x);
            }
            {
                std::lock_guard<std::mutex> lk(resMtx);
                stats.bytesScanned += rd;
                ++stats.regionsScanned;
            }
            processed += reg.size;
            if (progressCb) progressCb((float)processed / (float)totalBytes);
        });
    }
    pool.waitAll();

    session.results = std::move(allResults);
    session.type    = isWide ? ValueType::WString : ValueType::String;
    session.hasFirst = true;
    ++session.scanCount;

    auto t1 = std::chrono::high_resolution_clock::now();
    stats.elapsedMs    = std::chrono::duration<double, std::milli>(t1 - t0).count();
    stats.resultsFound = session.results.size();
    if (stats.elapsedMs > 0)
        stats.throughputMBs = (stats.bytesScanned/1024.0/1024.0) / (stats.elapsedMs/1000.0);
    scanning_ = false;
    return stats;
}

// ─── Pointer Scanner ─────────────────────────────────────────────────────────
void ScanEngine::pointerScan(uintptr_t targetAddr, int maxDepth, uintptr_t maxOffset,
                              std::vector<PointerChain>& outChains,
                              std::function<void(float)> progressCb) {
    // Simplified level-1 pointer scan: find all pointers to targetAddr ± maxOffset
    // then trace back through static module bases
    outChains.clear();
    if (!pe_.attached()) return;

    ScanOptions opts;
    opts.type        = pe_.is64bit() ? ValueType::UInt64 : ValueType::UInt32;
    opts.condition   = ScanCondition::Between;
    opts.protFilter  = ProtectionFilter::Readable;
    opts.regionFilter = RegionTypeFilter::All;
    opts.maxResults  = 2'000'000;

    auto regions = pe_.queryRegions(opts.protFilter, opts.regionFilter);
    size_t ptrSz = pe_.is64bit() ? 8 : 4;
    std::mutex chainMtx;
    size_t totalBytes = 0;
    for (auto& r : regions) totalBytes += r.size;
    std::atomic<size_t> processed{ 0 };

    size_t threadCount = std::max(1u, std::thread::hardware_concurrency());
    WorkerPool pool(threadCount);

    for (auto& reg : regions) {
        pool.enqueue([&, reg] {
            std::vector<uint8_t> buf(reg.size);
            SIZE_T rd = 0;
            if (!ReadProcessMemory(pe_.handle(), (LPCVOID)reg.base, buf.data(), reg.size, &rd)) return;
            for (size_t i = 0; i + ptrSz <= rd; i += ptrSz) {
                uintptr_t ptr = 0;
                memcpy(&ptr, buf.data() + i, ptrSz);
                if (ptr >= targetAddr - maxOffset && ptr <= targetAddr + maxOffset) {
                    uintptr_t srcAddr = reg.base + i;
                    // Check if source is in a module (static)
                    PointerChain chain;
                    for (auto& mod : pe_.procInfo().modules) {
                        if (srcAddr >= mod.base && srcAddr < mod.base + mod.size) {
                            chain.moduleName  = mod.name;
                            chain.moduleBase  = mod.base;
                            chain.baseOffset  = srcAddr - mod.base;
                            chain.offsets     = { targetAddr - ptr };
                            chain.type        = ValueType::Int32;
                            chain.name        = mod.name + "+" +
                                                ScanEngine::formatAddress(chain.baseOffset, pe_.is64bit());
                            break;
                        }
                    }
                    if (!chain.moduleName.empty()) {
                        std::lock_guard<std::mutex> lk(chainMtx);
                        outChains.push_back(chain);
                        if (outChains.size() > 10000) return;
                    }
                }
            }
            processed += reg.size;
            if (progressCb) progressCb((float)processed / (float)totalBytes);
        });
    }
    pool.waitAll();
}

// ─── Formatting ───────────────────────────────────────────────────────────────
std::string ScanEngine::valueToString(const ScanResult& r) {
    std::ostringstream ss;
    switch (r.type) {
        case ValueType::Int8:   ss << (int)(int8_t)(r.rawCurrent & 0xFF); break;
        case ValueType::UInt8:  ss << (unsigned)(r.rawCurrent & 0xFF); break;
        case ValueType::Int16:  ss << (int16_t)(r.rawCurrent & 0xFFFF); break;
        case ValueType::UInt16: ss << (uint16_t)(r.rawCurrent & 0xFFFF); break;
        case ValueType::Int32:  ss << (int32_t)(r.rawCurrent & 0xFFFFFFFF); break;
        case ValueType::UInt32: ss << (uint32_t)(r.rawCurrent & 0xFFFFFFFF); break;
        case ValueType::Int64:  ss << (int64_t)r.rawCurrent; break;
        case ValueType::UInt64: ss << r.rawCurrent; break;
        case ValueType::Float: {
            float f; memcpy(&f, &r.rawCurrent, 4);
            ss << std::fixed << std::setprecision(4) << f; break;
        }
        case ValueType::Double: {
            double d; memcpy(&d, &r.rawCurrent, 8);
            ss << std::fixed << std::setprecision(6) << d; break;
        }
        case ValueType::AoB:
        case ValueType::String:
        case ValueType::WString: {
            for (uint8_t b : r.extData) ss << std::hex << std::uppercase
                                            << std::setw(2) << std::setfill('0') << (int)b << ' ';
            break;
        }
        default: ss << r.rawCurrent; break;
    }
    return ss.str();
}

std::string ScanEngine::formatAddress(uintptr_t addr, bool is64) {
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    if (is64) ss << std::setw(16) << addr;
    else       ss << std::setw(8)  << (uint32_t)addr;
    return ss.str();
}
