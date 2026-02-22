#pragma once
#include "MemScanner.h"

class ProcessEngine {
public:
    ProcessEngine();
    ~ProcessEngine();

    // Process management
    static std::vector<ProcessInfo> listProcesses();
    bool         attach(DWORD pid);
    void         detach();
    bool         isAlive() const;
    void         refreshModules();

    // Memory query
    std::vector<MemRegion> queryRegions(ProtectionFilter pf, RegionTypeFilter rf) const;
    bool         readBytes(uintptr_t addr, void* buf, size_t sz) const;
    bool         writeBytes(uintptr_t addr, const void* buf, size_t sz) const;
    bool         protectRegion(uintptr_t addr, size_t sz, DWORD newProt, DWORD* oldProt) const;
    bool         allocateMemory(uintptr_t& outAddr, size_t sz, DWORD prot = PAGE_EXECUTE_READWRITE) const;
    bool         freeMemory(uintptr_t addr, size_t sz) const;

    // Pointer chain
    uintptr_t    resolvePointerChain(const PointerChain& chain) const;

    // Thread control
    void         suspend() const;
    void         resume()  const;
    std::vector<uint32_t> getThreadIDs() const;

    // Module helpers
    uintptr_t    getModuleBase(const std::string& modName) const;

    // Heap
    std::vector<HeapBlock> getHeapBlocks() const;

    // Accessors
    const ProcessInfo& procInfo() const { return proc_; }
    HANDLE             handle()   const { return proc_.handle; }
    bool               is64bit()  const { return proc_.is64bit; }
    DWORD              pid()      const { return proc_.pid; }
    bool               attached() const { return proc_.handle && proc_.handle != INVALID_HANDLE_VALUE; }

    // Utilities
    static std::string  wideToUtf8(const wchar_t* w);
    static std::wstring utf8ToWide(const std::string& s);

    template<typename T>
    bool read(uintptr_t addr, T& out) const {
        return readBytes(addr, &out, sizeof(T));
    }
    template<typename T>
    bool write(uintptr_t addr, const T& val) const {
        return writeBytes(addr, &val, sizeof(T));
    }

private:
    ProcessInfo proc_;
};
