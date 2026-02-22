#include "DisasmEngine.h"
#include "ScanEngine.h"
#include <sstream>
#include <iomanip>
#include <cassert>

// ─── Construction ─────────────────────────────────────────────────────────────
DisasmEngine::DisasmEngine(ProcessEngine& pe) : pe_(pe) {
    ZydisDecoderInit(&decoder64_, ZYDIS_MACHINE_MODE_LONG_64,   ZYDIS_STACK_WIDTH_64);
    ZydisDecoderInit(&decoder32_, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL);
    ZydisFormatterSetProperty(&formatter_,
        ZYDIS_FORMATTER_PROP_FORCE_SEGMENT,   ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter_,
        ZYDIS_FORMATTER_PROP_FORCE_SIZE,      ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter_,
        ZYDIS_FORMATTER_PROP_UPPERCASE_PREFIXES,  ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter_,
        ZYDIS_FORMATTER_PROP_UPPERCASE_MNEMONIC,  ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter_,
        ZYDIS_FORMATTER_PROP_UPPERCASE_REGISTERS, ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter_,
        ZYDIS_FORMATTER_PROP_UPPERCASE_TYPECASTS, ZYAN_TRUE);
}

DisasmEngine::~DisasmEngine() = default;

// ─── safeRead ─────────────────────────────────────────────────────────────────
size_t DisasmEngine::safeRead(uintptr_t addr, uint8_t* buf, size_t sz) const {
    SIZE_T rd = 0;
    ReadProcessMemory(pe_.handle(), (LPCVOID)addr, buf, sz, &rd);
    return (size_t)rd;
}

// ─── Formatting helpers ───────────────────────────────────────────────────────
std::string DisasmEngine::bytesToHex(const uint8_t* d, size_t len) {
    std::ostringstream ss;
    for (size_t i = 0; i < len; ++i)
        ss << std::hex << std::uppercase
           << std::setw(2) << std::setfill('0') << (int)d[i];
    return ss.str();
}

std::string DisasmEngine::addrToString(uintptr_t addr, bool is64) {
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    if (is64) ss << std::setw(16) << addr;
    else       ss << std::setw(8)  << (uint32_t)addr;
    return ss.str();
}

// ─── resolveOperandTarget ────────────────────────────────────────────────────
uintptr_t DisasmEngine::resolveOperandTarget(const ZydisDecodedInstruction& insn,
                                              const ZydisDecodedOperand*     ops,
                                              uintptr_t                      instrVA) const {
    for (uint8_t i = 0; i < insn.operand_count_visible; ++i) {
        const ZydisDecodedOperand& op = ops[i];
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (op.imm.is_relative) {
                ZyanU64 abs = 0;
                ZydisCalcAbsoluteAddress(&insn, &op, instrVA, &abs);
                return (uintptr_t)abs;
            }
            return (uintptr_t)op.imm.value.u;
        }
        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (op.mem.base == ZYDIS_REGISTER_RIP ||
                op.mem.base == ZYDIS_REGISTER_EIP ||
                op.mem.base == ZYDIS_REGISTER_NONE) {
                ZyanU64 abs = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &op, instrVA, &abs)))
                    return (uintptr_t)abs;
            }
        }
    }
    return 0;
}

// ─── disassembleBuffer ────────────────────────────────────────────────────────
std::vector<DisasmEntry> DisasmEngine::disassembleBuffer(const uint8_t* buf, size_t len,
                                                          uintptr_t runtimeAddr,
                                                          size_t maxInstr) {
    std::vector<DisasmEntry> result;
    result.reserve(std::min(maxInstr, len / 2 + 1));

    ZydisDecoder&          dec = activeDecoder();
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];

    size_t      off   = 0;
    size_t      count = 0;
    bool        is64  = pe_.is64bit();

    while (off < len && count < maxInstr) {
        uintptr_t va = runtimeAddr + off;

        ZyanStatus status = ZydisDecoderDecodeFull(&dec,
                                                    buf + off, len - off,
                                                    &insn, ops);
        if (!ZYAN_SUCCESS(status)) {
            // Emit a DB byte for undecodable data and advance by 1.
            DisasmEntry e;
            e.address  = va;
            e.length   = 1;
            e.bytes    = bytesToHex(buf + off, 1);
            e.mnemonic = "DB";
            e.operands = "0x" + bytesToHex(buf + off, 1);
            result.push_back(e);
            ++off;
            ++count;
            continue;
        }

        DisasmEntry e;
        e.address = va;
        e.length  = (uint8_t)insn.length;
        e.bytes   = bytesToHex(buf + off, insn.length);

        // Full formatted string from Zydis
        char formatted[256] = {};
        ZydisFormatterFormatInstruction(&formatter_, &insn, ops,
                                        insn.operand_count_visible,
                                        formatted, sizeof(formatted), va, nullptr);

        // Split at first space into mnemonic + operands
        std::string full(formatted);
        size_t sp = full.find(' ');
        if (sp != std::string::npos) {
            e.mnemonic = full.substr(0, sp);
            e.operands = full.substr(sp + 1);
        } else {
            e.mnemonic = full;
        }

        // Classify for colour coding in UI
        switch (insn.meta.category) {
            case ZYDIS_CATEGORY_CALL:
                e.isCall = true;
                // Annotate with symbol if we can resolve the target
                {
                    uintptr_t tgt = resolveOperandTarget(insn, ops, va);
                    if (tgt) {
                        std::string sym = resolveSymbolShort(tgt);
                        if (!sym.empty()) e.operands += "  ; <" + sym + ">";
                    }
                }
                break;
            case ZYDIS_CATEGORY_UNCOND_BR:
                e.isJump = true;
                break;
            case ZYDIS_CATEGORY_COND_BR:
                e.isJump = true;
                break;
            case ZYDIS_CATEGORY_RET:
                e.isRet = true;
                break;
            default:
                break;
        }

        result.push_back(e);
        off   += insn.length;
        ++count;
    }
    return result;
}

// ─── disassemble (reads from target) ─────────────────────────────────────────
std::vector<DisasmEntry> DisasmEngine::disassemble(uintptr_t addr, size_t count) {
    // Read a generous chunk; 15 bytes per instruction worst case.
    const size_t readSz = std::min(count * 15 + 15, (size_t)65536);
    std::vector<uint8_t> buf(readSz);
    size_t rd = safeRead(addr, buf.data(), readSz);
    if (rd == 0) return {};
    buf.resize(rd);
    return disassembleBuffer(buf.data(), rd, addr, count);
}

// ─── decodeOne ────────────────────────────────────────────────────────────────
bool DisasmEngine::decodeOne(uintptr_t addr, DisasmEntry& out) {
    uint8_t buf[ZYDIS_MAX_INSTRUCTION_LENGTH];
    size_t rd = safeRead(addr, buf, sizeof(buf));
    if (rd == 0) return false;

    auto entries = disassembleBuffer(buf, rd, addr, 1);
    if (entries.empty()) return false;
    out = entries[0];
    return true;
}

// ─── instrLen ─────────────────────────────────────────────────────────────────
size_t DisasmEngine::instrLen(uintptr_t addr) {
    uint8_t buf[ZYDIS_MAX_INSTRUCTION_LENGTH];
    size_t  rd = safeRead(addr, buf, sizeof(buf));
    if (rd == 0) return 0;

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&activeDecoder(), buf, rd, &insn, ops)))
        return 1;
    return insn.length;
}

// ─── traceJmpChain ────────────────────────────────────────────────────────────
std::vector<uintptr_t> DisasmEngine::traceJmpChain(uintptr_t addr, int maxDepth) {
    std::vector<uintptr_t> chain;
    std::unordered_map<uintptr_t, bool> visited;

    uintptr_t cur = addr;
    for (int depth = 0; depth < maxDepth; ++depth) {
        if (visited.count(cur)) break;
        visited[cur] = true;

        uint8_t buf[ZYDIS_MAX_INSTRUCTION_LENGTH];
        size_t rd = safeRead(cur, buf, sizeof(buf));
        if (rd == 0) break;

        ZydisDecodedInstruction insn;
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&activeDecoder(), buf, rd, &insn, ops)))
            break;

        bool isUnconditionalJmp =
            (insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
        bool isCall =
            (insn.meta.category == ZYDIS_CATEGORY_CALL);

        if (!isUnconditionalJmp && !isCall) break;

        uintptr_t tgt = resolveOperandTarget(insn, ops, cur);
        if (tgt == 0) break;

        chain.push_back(tgt);
        if (!isUnconditionalJmp) break; // stop chasing calls
        cur = tgt;
    }
    return chain;
}

// ─── Patch helpers ────────────────────────────────────────────────────────────
bool DisasmEngine::createPatch(const std::string& name, uintptr_t addr,
                                const std::vector<uint8_t>& newBytes, MemPatch& out) {
    out.name         = name;
    out.address      = addr;
    out.patchedBytes = newBytes;
    out.originalBytes.resize(newBytes.size(), 0);
    if (!pe_.readBytes(addr, out.originalBytes.data(), newBytes.size())) return false;
    out.applied = false;
    return true;
}

bool DisasmEngine::applyPatch(MemPatch& p) {
    if (p.applied) return true;
    if (!pe_.writeBytes(p.address, p.patchedBytes.data(), p.patchedBytes.size()))
        return false;
    p.applied = true;
    return true;
}

bool DisasmEngine::revertPatch(MemPatch& p) {
    if (!p.applied) return true;
    if (!pe_.writeBytes(p.address, p.originalBytes.data(), p.originalBytes.size()))
        return false;
    p.applied = false;
    return true;
}

bool DisasmEngine::nopRange(uintptr_t addr, size_t len, MemPatch& out) {
    std::vector<uint8_t> nops(len, 0x90);
    return createPatch("NOP@" + addrToString(addr, pe_.is64bit()), addr, nops, out);
}

bool DisasmEngine::writeRelJmp(uintptr_t from, uintptr_t to, MemPatch& out) {
    // Compute how many complete instructions we need to clobber to fit 5 bytes.
    size_t covered = 0;
    uintptr_t scan = from;
    while (covered < 5) {
        size_t l = instrLen(scan);
        if (l == 0) l = 1;
        covered += l;
        scan    += l;
    }
    std::vector<uint8_t> patch(covered, 0x90);
    int64_t rel64 = (int64_t)to - (int64_t)(from + 5);
    if (rel64 < INT32_MIN || rel64 > INT32_MAX) return false;
    int32_t rel32 = (int32_t)rel64;
    patch[0] = 0xE9;
    memcpy(patch.data() + 1, &rel32, 4);
    return createPatch("JMP@" + addrToString(from, pe_.is64bit()), from, patch, out);
}

bool DisasmEngine::writeRelCall(uintptr_t from, uintptr_t to, MemPatch& out) {
    size_t covered = 0;
    uintptr_t scan = from;
    while (covered < 5) {
        size_t l = instrLen(scan);
        if (l == 0) l = 1;
        covered += l;
        scan    += l;
    }
    std::vector<uint8_t> patch(covered, 0x90);
    int64_t rel64 = (int64_t)to - (int64_t)(from + 5);
    if (rel64 < INT32_MIN || rel64 > INT32_MAX) return false;
    int32_t rel32 = (int32_t)rel64;
    patch[0] = 0xE8;
    memcpy(patch.data() + 1, &rel32, 4);
    return createPatch("CALL@" + addrToString(from, pe_.is64bit()), from, patch, out);
}

bool DisasmEngine::writeAbsJmp64(uintptr_t from, uintptr_t to, MemPatch& out) {
    // FF 25 00 00 00 00  <8-byte absolute VA>   (14 bytes total)
    size_t covered = 0;
    uintptr_t scan = from;
    while (covered < 14) {
        size_t l = instrLen(scan);
        if (l == 0) l = 1;
        covered += l;
        scan    += l;
    }
    std::vector<uint8_t> patch(covered, 0x90);
    patch[0] = 0xFF; patch[1] = 0x25;
    patch[2] = patch[3] = patch[4] = patch[5] = 0x00; // RIP+0 disp
    memcpy(patch.data() + 6, &to, 8);
    return createPatch("ABSJMP64@" + addrToString(from, pe_.is64bit()), from, patch, out);
}

// ─── relocateInstruction ─────────────────────────────────────────────────────
bool DisasmEngine::relocateInstruction(const ZydisDecodedInstruction& insn,
                                        const ZydisDecodedOperand*     ops,
                                        uintptr_t srcVA, uintptr_t dstVA,
                                        std::vector<uint8_t>& out) {
    // Only RIP-relative instructions need fixup.  For everything else, emit as-is.
    bool hasRipRel = false;
    for (uint8_t i = 0; i < insn.operand_count; ++i) {
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            (ops[i].mem.base == ZYDIS_REGISTER_RIP ||
             ops[i].mem.base == ZYDIS_REGISTER_EIP)) {
            hasRipRel = true;
            break;
        }
    }
    if (insn.attributes & ZYDIS_ATTRIB_IS_RELATIVE) hasRipRel = true;

    if (!hasRipRel) {
        // Read raw bytes from target and copy verbatim.
        out.resize(insn.length);
        safeRead(srcVA, out.data(), insn.length);
        return true;
    }

    // For RIP-relative: recompute the displacement for the new location.
    // Strategy: read original bytes, find the displacement field and patch it.
    out.resize(insn.length);
    safeRead(srcVA, out.data(), insn.length);

    for (uint8_t i = 0; i < insn.operand_count; ++i) {
        const ZydisDecodedOperand& op = ops[i];
        // Branch with relative immediate
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
            ZyanU64 absTarget = 0;
            ZydisCalcAbsoluteAddress(&insn, &op, srcVA, &absTarget);
            int64_t newRel = (int64_t)absTarget - (int64_t)(dstVA + insn.length);

            uint8_t dispSz = insn.raw.imm[0].size / 8;
            uint8_t dispOff = insn.raw.imm[0].offset;
            if (dispSz == 1) {
                if (newRel < -128 || newRel > 127) return false; // can't relocate short branch
                out[dispOff] = (uint8_t)(int8_t)newRel;
            } else if (dispSz == 4) {
                if (newRel < INT32_MIN || newRel > INT32_MAX) return false;
                int32_t r32 = (int32_t)newRel;
                memcpy(out.data() + dispOff, &r32, 4);
            } else {
                return false;
            }
            return true;
        }
        // RIP-relative memory operand
        if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
            (op.mem.base == ZYDIS_REGISTER_RIP ||
             op.mem.base == ZYDIS_REGISTER_EIP)) {
            ZyanU64 absTarget = 0;
            ZydisCalcAbsoluteAddress(&insn, &op, srcVA, &absTarget);
            // New displacement: absTarget - (dstVA + insn.length)
            int64_t newDisp = (int64_t)absTarget - (int64_t)(dstVA + insn.length);
            if (newDisp < INT32_MIN || newDisp > INT32_MAX) return false;
            int32_t d32 = (int32_t)newDisp;
            uint8_t dispOff = insn.raw.disp.offset;
            memcpy(out.data() + dispOff, &d32, 4);
            return true;
        }
    }
    return true; // no displacement to fix
}

// ─── hookFunction ─────────────────────────────────────────────────────────────
bool DisasmEngine::hookFunction(uintptr_t targetAddr, uintptr_t hookFn,
                                 size_t minPatchBytes,
                                 uintptr_t& outTrampoline,
                                 MemPatch&  outPatch) {
    bool is64 = pe_.is64bit();
    size_t jmpSize = is64 ? 14 : 5; // ABS64 or rel32
    if (minPatchBytes < jmpSize) minPatchBytes = jmpSize;

    // 1. Disassemble enough instructions to cover minPatchBytes.
    std::vector<uint8_t> origBuf(minPatchBytes + 15 * 4);
    safeRead(targetAddr, origBuf.data(), origBuf.size());

    struct InsnRecord {
        uintptr_t        va;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
        size_t           rawOff;
    };
    std::vector<InsnRecord> stolen;
    size_t off = 0;
    while (off < minPatchBytes) {
        InsnRecord rec;
        rec.va     = targetAddr + off;
        rec.rawOff = off;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&activeDecoder(),
                origBuf.data() + off, origBuf.size() - off,
                &rec.insn, rec.ops)))
            return false;
        stolen.push_back(rec);
        off += rec.insn.length;
    }
    size_t totalStolen = off; // actual bytes clobbered (instruction-aligned)

    // 2. Allocate a trampoline cave.
    size_t trampolineSize = totalStolen + 15 * stolen.size() + jmpSize + 16;
    if (!allocCodeCave(targetAddr, trampolineSize, outTrampoline)) return false;

    // 3. Build trampoline: relocated stolen instructions + JMP back.
    std::vector<uint8_t> trampolineBuf;
    trampolineBuf.reserve(trampolineSize);
    uintptr_t tramWriteVA = outTrampoline;

    for (auto& rec : stolen) {
        std::vector<uint8_t> relocated;
        if (!relocateInstruction(rec.insn, rec.ops, rec.va, tramWriteVA, relocated))
            return false;
        trampolineBuf.insert(trampolineBuf.end(), relocated.begin(), relocated.end());
        tramWriteVA += relocated.size();
    }

    // JMP back to instruction after patch
    uintptr_t resumeVA = targetAddr + totalStolen;
    if (is64) {
        // FF 25 00 00 00 00 <8-byte abs>
        uint8_t jmpBack[14] = { 0xFF, 0x25, 0, 0, 0, 0 };
        memcpy(jmpBack + 6, &resumeVA, 8);
        trampolineBuf.insert(trampolineBuf.end(), jmpBack, jmpBack + 14);
    } else {
        int32_t rel = (int32_t)(resumeVA - (tramWriteVA + 5));
        uint8_t jmpBack[5] = { 0xE9 };
        memcpy(jmpBack + 1, &rel, 4);
        trampolineBuf.insert(trampolineBuf.end(), jmpBack, jmpBack + 5);
    }

    // Write trampoline into target.
    if (!pe_.writeBytes(outTrampoline, trampolineBuf.data(), trampolineBuf.size()))
        return false;

    // 4. Write the hook JMP at targetAddr.
    if (is64) {
        int64_t rel64 = (int64_t)hookFn - (int64_t)(targetAddr + 5);
        if (rel64 >= INT32_MIN && rel64 <= INT32_MAX)
            return writeRelJmp(targetAddr, hookFn, outPatch);
        else
            return writeAbsJmp64(targetAddr, hookFn, outPatch);
    }
    return writeRelJmp(targetAddr, hookFn, outPatch);
}

// ─── Code cave allocation ─────────────────────────────────────────────────────
bool DisasmEngine::allocCodeCave(uintptr_t nearAddr, size_t sz, uintptr_t& outAddr) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    uintptr_t lo = nearAddr >= 0x80000000ULL ? nearAddr - 0x7FFF0000ULL : (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t hi = nearAddr + 0x7FFF0000ULL;
    lo = std::max(lo, (uintptr_t)si.lpMinimumApplicationAddress);
    hi = std::min(hi, (uintptr_t)si.lpMaximumApplicationAddress);

    DWORD granularity = si.dwAllocationGranularity;
    for (uintptr_t probe = (nearAddr & ~(uintptr_t)(granularity - 1)); probe > lo; probe -= granularity) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(pe_.handle(), (LPCVOID)probe, &mbi, sizeof(mbi)) != sizeof(mbi)) continue;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= sz) {
            void* p = VirtualAllocEx(pe_.handle(), (LPVOID)probe, sz,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) { outAddr = (uintptr_t)p; return true; }
        }
    }
    for (uintptr_t probe = (nearAddr & ~(uintptr_t)(granularity - 1)) + granularity;
         probe < hi; probe += granularity) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(pe_.handle(), (LPCVOID)probe, &mbi, sizeof(mbi)) != sizeof(mbi)) continue;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= sz) {
            void* p = VirtualAllocEx(pe_.handle(), (LPVOID)probe, sz,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (p) { outAddr = (uintptr_t)p; return true; }
        }
    }
    return false;
}

bool DisasmEngine::injectShellcode(const std::vector<uint8_t>& code, uintptr_t& outAddr) {
    if (!pe_.allocateMemory(outAddr, code.size(), PAGE_EXECUTE_READWRITE)) return false;
    return pe_.writeBytes(outAddr, code.data(), code.size());
}

// ─── Symbol resolution ────────────────────────────────────────────────────────
bool DisasmEngine::loadSymbols() {
    if (dbgLoaded_) return true;
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS |
                  SYMOPT_LOAD_LINES | SYMOPT_INCLUDE_32BIT_MODULES);
    dbgLoaded_ = SymInitialize(pe_.handle(), nullptr, TRUE) != 0;
    return dbgLoaded_;
}

std::string DisasmEngine::resolveSymbol(uintptr_t addr) {
    if (!dbgLoaded_) loadSymbols();
    if (!dbgLoaded_) return {};
    alignas(SYMBOL_INFO) char raw[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
    SYMBOL_INFO* sym = (SYMBOL_INFO*)raw;
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen   = MAX_SYM_NAME;
    DWORD64 disp = 0;
    if (!SymFromAddr(pe_.handle(), (DWORD64)addr, &disp, sym)) return {};
    char modBuf[64] = {};
    IMAGEHLP_MODULE64 modInfo{ sizeof(modInfo) };
    if (SymGetModuleInfo64(pe_.handle(), (DWORD64)addr, &modInfo))
        snprintf(modBuf, sizeof(modBuf), "%s!", modInfo.ModuleName);
    std::string result = std::string(modBuf) + sym->Name;
    if (disp) result += "+" + std::to_string(disp);
    return result;
}

std::string DisasmEngine::resolveSymbolShort(uintptr_t addr) {
    if (!dbgLoaded_) loadSymbols();
    if (!dbgLoaded_) return {};
    alignas(SYMBOL_INFO) char raw[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
    SYMBOL_INFO* sym = (SYMBOL_INFO*)raw;
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen   = MAX_SYM_NAME;
    DWORD64 disp = 0;
    if (!SymFromAddr(pe_.handle(), (DWORD64)addr, &disp, sym)) return {};
    std::string result = sym->Name;
    if (disp) result += "+" + std::to_string(disp);
    return result;
}

uintptr_t DisasmEngine::symbolToAddress(const std::string& name) {
    if (!dbgLoaded_) loadSymbols();
    if (!dbgLoaded_) return 0;
    alignas(SYMBOL_INFO) char raw[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
    SYMBOL_INFO* sym = (SYMBOL_INFO*)raw;
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen   = MAX_SYM_NAME;
    if (!SymFromName(pe_.handle(), name.c_str(), sym)) return 0;
    return (uintptr_t)sym->Address;
}

// ─── PE parser ────────────────────────────────────────────────────────────────
std::string DisasmEngine::sectionCharString(DWORD ch) {
    std::string s;
    if (ch & IMAGE_SCN_MEM_READ)    s += 'R';
    if (ch & IMAGE_SCN_MEM_WRITE)   s += 'W';
    if (ch & IMAGE_SCN_MEM_EXECUTE) s += 'X';
    if (ch & IMAGE_SCN_CNT_CODE)              s += " CODE";
    if (ch & IMAGE_SCN_CNT_INITIALIZED_DATA)  s += " IDATA";
    if (ch & IMAGE_SCN_CNT_UNINITIALIZED_DATA) s += " UDATA";
    return s;
}

DisasmEngine::PEInfo DisasmEngine::parsePE(uintptr_t moduleBase) {
    PEInfo info{};
    info.moduleBase = moduleBase;
    if (!pe_.attached()) return info;

    IMAGE_DOS_HEADER dos{};
    if (!pe_.read(moduleBase, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return info;

    // Peek at Machine field to determine bitness
    DWORD sig = 0;
    uintptr_t ntBase = moduleBase + dos.e_lfanew;
    pe_.read(ntBase, sig);
    if (sig != IMAGE_NT_SIGNATURE) return info;

    uint16_t machine = 0;
    pe_.read(ntBase + 4, machine);
    bool is64 = (machine == IMAGE_FILE_MACHINE_AMD64);
    info.arch = is64 ? "x86-64" : "x86-32";

    // Read the appropriate NT headers struct.
    if (is64) {
        IMAGE_NT_HEADERS64 nt{};
        if (!pe_.read(ntBase, nt)) return info;
        info.entryPoint         = moduleBase + nt.OptionalHeader.AddressOfEntryPoint;
        info.imageBase          = nt.OptionalHeader.ImageBase;
        info.sizeOfImage        = nt.OptionalHeader.SizeOfImage;
        info.characteristics    = nt.FileHeader.Characteristics;
        info.dllCharacteristics = nt.OptionalHeader.DllCharacteristics;
        info.checksum           = nt.OptionalHeader.CheckSum;
        info.subsystem          = nt.OptionalHeader.Subsystem;
        info.isDLL   = (info.characteristics & IMAGE_FILE_DLL) != 0;
        info.isASLR  = (info.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
        info.isDEP   = (info.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
        info.isCFG   = (info.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
        info.isSEH   = (info.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;

        for (int i = 0; i < 16; ++i) {
            info.dataDirectories[i].rva  = nt.OptionalHeader.DataDirectory[i].VirtualAddress;
            info.dataDirectories[i].size = nt.OptionalHeader.DataDirectory[i].Size;
        }

        // Subsystem name
        switch (nt.OptionalHeader.Subsystem) {
            case IMAGE_SUBSYSTEM_WINDOWS_GUI:     info.subsystemName = "Windows GUI"; break;
            case IMAGE_SUBSYSTEM_WINDOWS_CUI:     info.subsystemName = "Console";     break;
            case IMAGE_SUBSYSTEM_NATIVE:          info.subsystemName = "Native";      break;
            case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:  info.subsystemName = "WinCE GUI";   break;
            case IMAGE_SUBSYSTEM_EFI_APPLICATION: info.subsystemName = "EFI App";     break;
            default: info.subsystemName = std::to_string(nt.OptionalHeader.Subsystem); break;
        }

        // ── Sections ──
        uintptr_t sectBase = ntBase
            + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
            + nt.FileHeader.SizeOfOptionalHeader;
        for (int i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER sec{};
            if (!pe_.read(sectBase + (size_t)i * sizeof(sec), sec)) break;
            SectionInfo si;
            si.name        .assign((char*)sec.Name, strnlen((char*)sec.Name, 8));
            si.rva          = sec.VirtualAddress;
            si.vaStart      = moduleBase + sec.VirtualAddress;
            si.rawSize      = sec.SizeOfRawData;
            si.virtualSize  = sec.Misc.VirtualSize;
            si.characteristics = sec.Characteristics;
            si.charString   = sectionCharString(sec.Characteristics);
            info.sections.push_back(std::move(si));
        }

        // ── Imports ──
        auto& impDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (impDir.VirtualAddress && impDir.Size) {
            uintptr_t cursor = moduleBase + impDir.VirtualAddress;
            for (;;) {
                IMAGE_IMPORT_DESCRIPTOR desc{};
                if (!pe_.read(cursor, desc)) break;
                if (!desc.Name && !desc.FirstThunk) break;

                char dll[256] = {};
                pe_.readBytes(moduleBase + desc.Name, dll, 255);
                ImportEntry ie; ie.dll = dll;

                uintptr_t origThunk = moduleBase + (desc.OriginalFirstThunk
                                                     ? desc.OriginalFirstThunk
                                                     : desc.FirstThunk);
                uintptr_t iatThunk  = moduleBase + desc.FirstThunk;
                for (size_t slot = 0; ; ++slot) {
                    uint64_t entry = 0;
                    if (!pe_.read(origThunk + slot * 8, entry) || entry == 0) break;
                    ImportEntry::Func fn;
                    fn.iatVA     = iatThunk + slot * 8;
                    fn.byOrdinal = (entry >> 63) & 1;
                    if (fn.byOrdinal) {
                        fn.ordinal = (uint16_t)(entry & 0xFFFF);
                        fn.name    = "#" + std::to_string(fn.ordinal);
                    } else {
                        char name[256] = {};
                        pe_.readBytes(moduleBase + (entry & 0x7FFFFFFFFFFFFFFF) + 2, name, 255);
                        fn.name    = name;
                        fn.ordinal = 0;
                    }
                    ie.funcs.push_back(fn);
                    if (ie.funcs.size() >= 4096) break;
                }
                info.imports.push_back(std::move(ie));
                cursor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            }
        }

        // ── Exports ──
        auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDir.VirtualAddress && expDir.Size) {
            uintptr_t expBase = moduleBase + expDir.VirtualAddress;
            IMAGE_EXPORT_DIRECTORY expD{};
            if (pe_.read(expBase, expD)) {
                uint32_t nameCount = std::min((DWORD)expD.NumberOfNames, (DWORD)8192);
                for (uint32_t i = 0; i < nameCount; ++i) {
                    uint32_t nameRva = 0, funcRva = 0;
                    uint16_t ordIdx  = 0;
                    pe_.read(moduleBase + expD.AddressOfNames        + i * 4, nameRva);
                    pe_.read(moduleBase + expD.AddressOfNameOrdinals + i * 2, ordIdx);
                    pe_.read(moduleBase + expD.AddressOfFunctions    + ordIdx * 4, funcRva);
                    char fn[256] = {};
                    pe_.readBytes(moduleBase + nameRva, fn, 255);
                    ExportEntry ex;
                    ex.name    = fn;
                    ex.rva     = funcRva;
                    ex.va      = moduleBase + funcRva;
                    ex.ordinal = (uint16_t)(ordIdx + expD.Base);
                    // Detect forwarder: if funcRva is inside the export directory
                    ex.isForward = (funcRva >= expDir.VirtualAddress &&
                                    funcRva <  expDir.VirtualAddress + expDir.Size);
                    if (ex.isForward) {
                        char fwd[256] = {};
                        pe_.readBytes(moduleBase + funcRva, fwd, 255);
                        ex.forwardName = fwd;
                    }
                    info.exports.push_back(ex);
                }
            }
        }

        // ── TLS callbacks ──
        auto& tlsDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir.VirtualAddress && tlsDir.Size) {
            IMAGE_TLS_DIRECTORY64 tls{};
            if (pe_.read(moduleBase + tlsDir.VirtualAddress, tls) &&
                tls.AddressOfCallBacks) {
                uintptr_t cbPtr = (uintptr_t)tls.AddressOfCallBacks;
                for (size_t idx = 0; idx < 64; ++idx) {
                    uint64_t cbVA = 0;
                    if (!pe_.read(cbPtr + idx * 8, cbVA) || cbVA == 0) break;
                    TLSEntry te; te.callbackVA = (uintptr_t)cbVA; te.index = idx;
                    info.tlsCallbacks.push_back(te);
                }
            }
        }
    } else {
        // 32-bit path
        IMAGE_NT_HEADERS32 nt{};
        if (!pe_.read(ntBase, nt)) return info;
        info.entryPoint         = moduleBase + nt.OptionalHeader.AddressOfEntryPoint;
        info.imageBase          = nt.OptionalHeader.ImageBase;
        info.sizeOfImage        = nt.OptionalHeader.SizeOfImage;
        info.characteristics    = nt.FileHeader.Characteristics;
        info.dllCharacteristics = nt.OptionalHeader.DllCharacteristics;
        info.checksum           = nt.OptionalHeader.CheckSum;
        info.subsystem          = nt.OptionalHeader.Subsystem;
        info.isDLL   = (info.characteristics & IMAGE_FILE_DLL) != 0;
        info.isASLR  = (info.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
        info.isDEP   = (info.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
        info.isCFG   = (info.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
        info.isSEH   = (info.dllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) == 0;
        for (int i = 0; i < 16; ++i) {
            info.dataDirectories[i].rva  = nt.OptionalHeader.DataDirectory[i].VirtualAddress;
            info.dataDirectories[i].size = nt.OptionalHeader.DataDirectory[i].Size;
        }
        // Sections
        uintptr_t sectBase = ntBase
            + offsetof(IMAGE_NT_HEADERS32, OptionalHeader)
            + nt.FileHeader.SizeOfOptionalHeader;
        for (int i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER sec{};
            if (!pe_.read(sectBase + (size_t)i * sizeof(sec), sec)) break;
            SectionInfo si;
            si.name.assign((char*)sec.Name, strnlen((char*)sec.Name, 8));
            si.rva         = sec.VirtualAddress;
            si.vaStart     = moduleBase + sec.VirtualAddress;
            si.rawSize     = sec.SizeOfRawData;
            si.virtualSize = sec.Misc.VirtualSize;
            si.characteristics = sec.Characteristics;
            si.charString  = sectionCharString(sec.Characteristics);
            info.sections.push_back(std::move(si));
        }
        // Imports (32-bit thunks are 4-byte)
        auto& impDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (impDir.VirtualAddress && impDir.Size) {
            uintptr_t cursor = moduleBase + impDir.VirtualAddress;
            for (;;) {
                IMAGE_IMPORT_DESCRIPTOR desc{};
                if (!pe_.read(cursor, desc)) break;
                if (!desc.Name && !desc.FirstThunk) break;
                char dll[256] = {};
                pe_.readBytes(moduleBase + desc.Name, dll, 255);
                ImportEntry ie; ie.dll = dll;
                uintptr_t origThunk = moduleBase + (desc.OriginalFirstThunk
                                                     ? desc.OriginalFirstThunk
                                                     : desc.FirstThunk);
                uintptr_t iatThunk  = moduleBase + desc.FirstThunk;
                for (size_t slot = 0; ; ++slot) {
                    uint32_t entry = 0;
                    if (!pe_.read(origThunk + slot * 4, entry) || entry == 0) break;
                    ImportEntry::Func fn;
                    fn.iatVA     = iatThunk + slot * 4;
                    fn.byOrdinal = (entry >> 31) & 1;
                    if (fn.byOrdinal) {
                        fn.ordinal = (uint16_t)(entry & 0xFFFF);
                        fn.name    = "#" + std::to_string(fn.ordinal);
                    } else {
                        char name[256] = {};
                        pe_.readBytes(moduleBase + (entry & 0x7FFFFFFF) + 2, name, 255);
                        fn.name = name;
                    }
                    ie.funcs.push_back(fn);
                    if (ie.funcs.size() >= 4096) break;
                }
                info.imports.push_back(std::move(ie));
                cursor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            }
        }
        // Exports (32-bit)
        auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDir.VirtualAddress && expDir.Size) {
            uintptr_t expBase = moduleBase + expDir.VirtualAddress;
            IMAGE_EXPORT_DIRECTORY expD{};
            if (pe_.read(expBase, expD)) {
                uint32_t nameCount = std::min((DWORD)expD.NumberOfNames, (DWORD)8192);
                for (uint32_t i = 0; i < nameCount; ++i) {
                    uint32_t nameRva = 0, funcRva = 0;
                    uint16_t ordIdx  = 0;
                    pe_.read(moduleBase + expD.AddressOfNames + i * 4, nameRva);
                    pe_.read(moduleBase + expD.AddressOfNameOrdinals + i * 2, ordIdx);
                    pe_.read(moduleBase + expD.AddressOfFunctions + ordIdx * 4, funcRva);
                    char fn[256] = {};
                    pe_.readBytes(moduleBase + nameRva, fn, 255);
                    ExportEntry ex;
                    ex.name    = fn;
                    ex.rva     = funcRva;
                    ex.va      = moduleBase + funcRva;
                    ex.ordinal = (uint16_t)(ordIdx + expD.Base);
                    ex.isForward = (funcRva >= expDir.VirtualAddress &&
                                    funcRva <  expDir.VirtualAddress + expDir.Size);
                    if (ex.isForward) {
                        char fwd[256] = {};
                        pe_.readBytes(moduleBase + funcRva, fwd, 255);
                        ex.forwardName = fwd;
                    }
                    info.exports.push_back(ex);
                }
            }
        }
    }
    return info;
}

// ─── XRef scan ────────────────────────────────────────────────────────────────
std::vector<DisasmEngine::XRef> DisasmEngine::findXRefs(uintptr_t targetAddr,
                                                         uintptr_t scanBase, size_t scanLen) {
    std::vector<XRef> xrefs;
    std::vector<uint8_t> buf(scanLen);
    size_t rd = safeRead(scanBase, buf.data(), scanLen);
    if (rd == 0) return xrefs;

    ZydisDecoder&          dec = activeDecoder();
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
    size_t off = 0;

    while (off < rd) {
        uintptr_t va = scanBase + off;
        ZyanStatus st = ZydisDecoderDecodeFull(&dec, buf.data() + off, rd - off, &insn, ops);
        if (!ZYAN_SUCCESS(st)) { ++off; continue; }

        for (uint8_t i = 0; i < insn.operand_count_visible; ++i) {
            ZyanU64 abs = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[i], va, &abs)) &&
                (uintptr_t)abs == targetAddr) {
                XRef x;
                x.from = va;
                switch (insn.meta.category) {
                    case ZYDIS_CATEGORY_CALL:      x.type = "CALL";  break;
                    case ZYDIS_CATEGORY_UNCOND_BR: x.type = "JMP";   break;
                    case ZYDIS_CATEGORY_COND_BR:   x.type = "Jcc";   break;
                    default: {
                        const char* mn = ZydisMnemonicGetString(insn.mnemonic);
                        x.type = mn ? mn : "REF";
                        break;
                    }
                }
                char fmt[256] = {};
                ZydisFormatterFormatInstruction(&formatter_, &insn, ops,
                    insn.operand_count_visible, fmt, sizeof(fmt), va, nullptr);
                x.context = fmt;
                xrefs.push_back(x);
                break; // one XRef per instruction is enough
            }
        }
        off += insn.length;
    }
    return xrefs;
}

std::vector<DisasmEngine::XRef> DisasmEngine::findXRefsGlobal(
        uintptr_t targetAddr, std::function<void(float)> progressCb) {
    std::vector<XRef> all;
    auto regions = pe_.queryRegions(ProtectionFilter::Readable | ProtectionFilter::Executable,
                                    RegionTypeFilter::All);
    size_t totalBytes = 0;
    for (auto& r : regions) totalBytes += r.size;
    size_t processed = 0;
    for (auto& reg : regions) {
        auto found = findXRefs(targetAddr, reg.base, reg.size);
        all.insert(all.end(), found.begin(), found.end());
        processed += reg.size;
        if (progressCb && totalBytes > 0)
            progressCb((float)processed / (float)totalBytes);
    }
    return all;
}
