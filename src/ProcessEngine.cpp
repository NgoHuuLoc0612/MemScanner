#include "MemScanner.h"
#include "ProcessEngine.h"
#include <ntstatus.h>

// ─── MemRegion helpers ────────────────────────────────────────────────────────
bool MemRegion::isReadable() const {
    return protect & (PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|
                      PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY);
}
bool MemRegion::isWritable() const {
    return protect & (PAGE_READWRITE|PAGE_WRITECOPY|
                      PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY);
}
bool MemRegion::isExecutable() const {
    return protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|
                      PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY);
}
std::string MemRegion::protectString() const {
    if (state != MEM_COMMIT) return "FREE";
    std::string s;
    if (protect & PAGE_EXECUTE_READWRITE)  s = "RWX";
    else if (protect & PAGE_EXECUTE_READ)  s = "RX";
    else if (protect & PAGE_READWRITE)     s = "RW";
    else if (protect & PAGE_READONLY)      s = "R";
    else if (protect & PAGE_EXECUTE)       s = "X";
    else if (protect & PAGE_WRITECOPY)     s = "WC";
    else                                   s = "---";
    if (protect & PAGE_GUARD) s += "+G";
    if (protect & PAGE_NOCACHE) s += "+NC";
    return s;
}
std::string MemRegion::typeString() const {
    switch (type) {
        case MEM_IMAGE:   return "IMG";
        case MEM_MAPPED:  return "MAP";
        case MEM_PRIVATE: return "PRV";
        default:          return "---";
    }
}

// ─── ProcessEngine ────────────────────────────────────────────────────────────
ProcessEngine::ProcessEngine() = default;
ProcessEngine::~ProcessEngine() { detach(); }

std::vector<ProcessInfo> ProcessEngine::listProcesses() {
    std::vector<ProcessInfo> list;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return list;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return list; }
    do {
        ProcessInfo info;
        info.pid  = pe.th32ProcessID;
        info.name = wideToUtf8(pe.szExeFile);
        info.numThreads = pe.cntThreads;
        // try to open for query
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
        if (h) {
            wchar_t path[MAX_PATH] = {};
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(h, 0, path, &sz))
                info.path = wideToUtf8(path);
            BOOL wow = FALSE;
            IsWow64Process(h, &wow);
            info.is64bit = !wow;
            PROCESS_MEMORY_COUNTERS_EX pmc{ sizeof(pmc) };
            if (GetProcessMemoryInfo(h, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                info.workingSet     = pmc.WorkingSetSize;
                info.peakWorkingSet = pmc.PeakWorkingSetSize;
            }
            CloseHandle(h);
        }
        list.push_back(std::move(info));
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    std::sort(list.begin(), list.end(), [](auto& a, auto& b){ return a.name < b.name; });
    return list;
}

bool ProcessEngine::attach(DWORD pid) {
    detach();
    HANDLE h = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME |
        PROCESS_CREATE_THREAD | PROCESS_SET_INFORMATION, FALSE, pid);
    if (!h || h == INVALID_HANDLE_VALUE) return false;
    proc_.handle = h;
    proc_.pid    = pid;
    BOOL wow = FALSE; IsWow64Process(h, &wow);
    proc_.is64bit = !wow;
    wchar_t path[MAX_PATH] = {};
    DWORD sz = MAX_PATH;
    if (QueryFullProcessImageNameW(h, 0, path, &sz)) {
        proc_.path = wideToUtf8(path);
        proc_.name = std::filesystem::path(proc_.path).filename().string();
    }
    refreshModules();
    return true;
}

void ProcessEngine::detach() {
    if (proc_.handle && proc_.handle != INVALID_HANDLE_VALUE) {
        CloseHandle(proc_.handle);
        proc_.handle = INVALID_HANDLE_VALUE;
    }
    proc_ = {};
}

bool ProcessEngine::isAlive() const {
    if (!proc_.handle || proc_.handle == INVALID_HANDLE_VALUE) return false;
    DWORD code = 0;
    return GetExitCodeProcess(proc_.handle, &code) && code == STILL_ACTIVE;
}

void ProcessEngine::refreshModules() {
    proc_.modules.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc_.pid);
    if (snap == INVALID_HANDLE_VALUE) return;
    MODULEENTRY32W me{ sizeof(me) };
    if (Module32FirstW(snap, &me)) {
        do {
            ModuleInfo mi;
            mi.name   = wideToUtf8(me.szModule);
            mi.path   = wideToUtf8(me.szExePath);
            mi.base   = (uintptr_t)me.modBaseAddr;
            mi.size   = me.modBaseSize;
            mi.is64bit = proc_.is64bit;
            proc_.modules.push_back(std::move(mi));
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
}

std::vector<MemRegion> ProcessEngine::queryRegions(ProtectionFilter pf, RegionTypeFilter rf) const {
    std::vector<MemRegion> regions;
    if (!proc_.handle || proc_.handle == INVALID_HANDLE_VALUE) return regions;
    uintptr_t addr = 0;
    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQueryEx(proc_.handle, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS))
        {
            // type filter
            bool typeOk = false;
            if ((rf & RegionTypeFilter::Private) && mbi.Type == MEM_PRIVATE) typeOk = true;
            if ((rf & RegionTypeFilter::Mapped)  && mbi.Type == MEM_MAPPED)  typeOk = true;
            if ((rf & RegionTypeFilter::Image)   && mbi.Type == MEM_IMAGE)   typeOk = true;

            // prot filter
            bool protOk = false;
            if (pf & ProtectionFilter::Readable) {
                if (mbi.Protect & (PAGE_READONLY|PAGE_READWRITE|PAGE_WRITECOPY|
                    PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))
                    protOk = true;
            }
            if (pf & ProtectionFilter::Writable) {
                if (mbi.Protect & (PAGE_READWRITE|PAGE_WRITECOPY|
                    PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))
                    protOk = true;
            }
            if (pf & ProtectionFilter::Executable) {
                if (mbi.Protect & (PAGE_EXECUTE|PAGE_EXECUTE_READ|
                    PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))
                    protOk = true;
            }

            if (typeOk && protOk) {
                MemRegion r;
                r.base    = (uintptr_t)mbi.BaseAddress;
                r.size    = mbi.RegionSize;
                r.protect = mbi.Protect;
                r.state   = mbi.State;
                r.type    = mbi.Type;
                // find module name for image regions
                if (mbi.Type == MEM_IMAGE) {
                    for (auto& mod : proc_.modules)
                        if ((uintptr_t)mbi.AllocationBase == mod.base)
                            r.moduleName = mod.name;
                }
                regions.push_back(r);
            }
        }
        if (addr + mbi.RegionSize <= addr) break;
        addr += mbi.RegionSize;
    }
    return regions;
}

bool ProcessEngine::readBytes(uintptr_t addr, void* buf, size_t sz) const {
    SIZE_T read = 0;
    return ReadProcessMemory(proc_.handle, (LPCVOID)addr, buf, sz, &read) && read == sz;
}

bool ProcessEngine::writeBytes(uintptr_t addr, const void* buf, size_t sz) const {
    DWORD oldProt = 0;
    VirtualProtectEx(proc_.handle, (LPVOID)addr, sz, PAGE_EXECUTE_READWRITE, &oldProt);
    SIZE_T written = 0;
    bool ok = WriteProcessMemory(proc_.handle, (LPVOID)addr, buf, sz, &written) && written == sz;
    VirtualProtectEx(proc_.handle, (LPVOID)addr, sz, oldProt, &oldProt);
    return ok;
}

bool ProcessEngine::protectRegion(uintptr_t addr, size_t sz, DWORD newProt, DWORD* oldProt) const {
    return VirtualProtectEx(proc_.handle, (LPVOID)addr, sz, newProt, oldProt) != 0;
}

bool ProcessEngine::allocateMemory(uintptr_t& outAddr, size_t sz, DWORD prot) const {
    void* p = VirtualAllocEx(proc_.handle, nullptr, sz, MEM_COMMIT | MEM_RESERVE, prot);
    if (!p) return false;
    outAddr = (uintptr_t)p;
    return true;
}

bool ProcessEngine::freeMemory(uintptr_t addr, size_t sz) const {
    return VirtualFreeEx(proc_.handle, (LPVOID)addr, sz, MEM_DECOMMIT) != 0;
}

uintptr_t ProcessEngine::resolvePointerChain(const PointerChain& chain) const {
    if (!proc_.handle || proc_.handle == INVALID_HANDLE_VALUE) return 0;
    uintptr_t addr = chain.moduleBase + chain.baseOffset;
    for (size_t i = 0; i < chain.offsets.size(); ++i) {
        uintptr_t ptr = 0;
        size_t ptrSz  = proc_.is64bit ? 8 : 4;
        if (!readBytes(addr, &ptr, ptrSz)) return 0;
        addr = ptr + chain.offsets[i];
    }
    return addr;
}

std::string ProcessEngine::wideToUtf8(const wchar_t* w) {
    if (!w || !*w) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(sz - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), sz, nullptr, nullptr);
    return s;
}

std::wstring ProcessEngine::utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(sz - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), sz);
    return w;
}

void ProcessEngine::suspend() const {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, proc_.pid);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == proc_.pid) {
                HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (t) { SuspendThread(t); CloseHandle(t); }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

void ProcessEngine::resume() const {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, proc_.pid);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == proc_.pid) {
                HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (t) { ResumeThread(t); CloseHandle(t); }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

std::vector<uint32_t> ProcessEngine::getThreadIDs() const {
    std::vector<uint32_t> ids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, proc_.pid);
    if (snap == INVALID_HANDLE_VALUE) return ids;
    THREADENTRY32 te{ sizeof(te) };
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == proc_.pid)
                ids.push_back(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return ids;
}

uintptr_t ProcessEngine::getModuleBase(const std::string& modName) const {
    for (auto& m : proc_.modules)
        if (_stricmp(m.name.c_str(), modName.c_str()) == 0)
            return m.base;
    return 0;
}

std::vector<HeapBlock> ProcessEngine::getHeapBlocks() const {
    std::vector<HeapBlock> blocks;
    // Walk heap list via HEAPLIST32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, proc_.pid);
    if (snap == INVALID_HANDLE_VALUE) return blocks;
    HEAPLIST32 hl{ sizeof(hl) };
    if (Heap32ListFirst(snap, &hl)) {
        do {
            HEAPENTRY32 he{ sizeof(he) };
            if (Heap32First(&he, proc_.pid, hl.th32HeapID)) {
                do {
                    HeapBlock blk;
                    blk.address = (uintptr_t)he.dwAddress;
                    blk.size    = he.dwBlockSize;
                    blk.flags   = he.dwFlags;
                    blk.isBusy  = (he.dwFlags & LF32_FIXED) != 0;
                    blocks.push_back(blk);
                } while (Heap32Next(&he));
            }
        } while (Heap32ListNext(snap, &hl));
    }
    CloseHandle(snap);
    return blocks;
}
