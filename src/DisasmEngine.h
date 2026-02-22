#pragma once
#include "MemScanner.h"
#include "ProcessEngine.h"

// Zydis public API — amalgamated single-header build.
// Place Zydis.h + Zydis.c at: src/zydis/
// Download: https://github.com/zyantific/zydis/releases → zydis-v4.x.x-amalgamated.zip
#include "zydis/Zydis.h"

#include <DbgHelp.h>

// ─── DisasmEngine ─────────────────────────────────────────────────────────────
// Full x86/x64 disassembler backed entirely by Zydis v4.
// All instruction decoding, formatting, length computation and operand analysis
// is delegated to Zydis — zero hand-rolled opcode tables anywhere in this file.
class DisasmEngine {
public:
    explicit DisasmEngine(ProcessEngine& pe);
    ~DisasmEngine();

    // ── Disassembly ──────────────────────────────────────────────────────────

    // Disassemble up to `count` instructions from the target process at `addr`.
    std::vector<DisasmEntry> disassemble(uintptr_t addr, size_t count = 64);

    // Disassemble a host-side buffer that represents code at `runtimeAddr` in the target.
    std::vector<DisasmEntry> disassembleBuffer(const uint8_t* buf, size_t len,
                                               uintptr_t runtimeAddr,
                                               size_t maxInstr = 512);

    // Decode a single instruction at `addr`; returns false on failure.
    bool decodeOne(uintptr_t addr, DisasmEntry& out);

    // Follow a JMP / CALL chain from `addr` up to `maxDepth` levels.
    // Returns every resolved target VA encountered.
    std::vector<uintptr_t> traceJmpChain(uintptr_t addr, int maxDepth = 16);

    // Return the byte length of the instruction at `addr` (reads from target).
    size_t instrLen(uintptr_t addr);

    // ── Formatting ───────────────────────────────────────────────────────────
    static std::string bytesToHex(const uint8_t* d, size_t len);
    static std::string addrToString(uintptr_t addr, bool is64);

    // ── Patch management ─────────────────────────────────────────────────────

    // Populate a MemPatch (reads originals, stores patch bytes). Does NOT write yet.
    bool createPatch(const std::string& name, uintptr_t addr,
                     const std::vector<uint8_t>& newBytes, MemPatch& outPatch);
    bool applyPatch (MemPatch& patch);
    bool revertPatch(MemPatch& patch);

    // Fill `len` bytes at `addr` with 0x90 NOP.
    bool nopRange(uintptr_t addr, size_t len, MemPatch& outPatch);

    // 5-byte relative JMP (E9 rel32).  Remainder bytes are NOP-padded if `len` > 5.
    // `from` and `to` must be within ±2 GB.
    bool writeRelJmp(uintptr_t from, uintptr_t to, MemPatch& outPatch);

    // 5-byte relative CALL (E8 rel32).
    bool writeRelCall(uintptr_t from, uintptr_t to, MemPatch& outPatch);

    // 14-byte absolute indirect JMP for x64 when target is outside ±2 GB:
    //   FF 25 00 00 00 00  <8-byte little-endian absolute VA>
    bool writeAbsJmp64(uintptr_t from, uintptr_t to, MemPatch& outPatch);

    // Mid-function detour hook:
    //   1. Disassemble enough instructions at `targetAddr` to cover `minPatchBytes`.
    //   2. Allocate a trampoline cave near `targetAddr`.
    //   3. Copy clobbered instructions to the trampoline (Zydis relocation-aware).
    //   4. Append a JMP back to the instruction after the patch.
    //   5. Write a JMP (or ABS JMP64) to `hookFn` at `targetAddr`.
    // Returns the trampoline entry point in `outTrampoline`.
    bool hookFunction(uintptr_t targetAddr, uintptr_t hookFn,
                      size_t    minPatchBytes,
                      uintptr_t& outTrampoline,
                      MemPatch&  outPatch);

    // ── Code cave / allocation ────────────────────────────────────────────────

    // Find a MEM_FREE region within ±2 GB of `nearAddr`, allocate PAGE_EXECUTE_READWRITE.
    bool allocCodeCave(uintptr_t nearAddr, size_t sz, uintptr_t& outAddr);

    // Allocate anywhere in the target and write shellcode into it.
    bool injectShellcode(const std::vector<uint8_t>& code, uintptr_t& outAddr);

    // ── Symbol resolution (DbgHelp) ──────────────────────────────────────────
    bool        loadSymbols();
    std::string resolveSymbol(uintptr_t addr);         // "module!Func+offset"
    std::string resolveSymbolShort(uintptr_t addr);    // "Func+offset"
    uintptr_t   symbolToAddress(const std::string& qualifiedName); // inverse

    // ── PE header analysis ───────────────────────────────────────────────────
    struct SectionInfo {
        std::string name;
        uintptr_t   rva;
        uintptr_t   vaStart;
        size_t      rawSize;
        size_t      virtualSize;
        DWORD       characteristics;
        std::string charString;
    };
    struct ImportEntry {
        std::string dll;
        struct Func {
            std::string name;
            uint16_t    ordinal;
            uintptr_t   iatVA;
            bool        byOrdinal;
        };
        std::vector<Func> funcs;
    };
    struct ExportEntry {
        std::string name;
        uintptr_t   rva;
        uintptr_t   va;
        uint16_t    ordinal;
        bool        isForward;
        std::string forwardName;
    };
    struct TLSEntry {
        uintptr_t callbackVA;
        size_t    index;
    };
    struct PEInfo {
        std::string              arch;
        uintptr_t                moduleBase;
        uintptr_t                entryPoint;
        uintptr_t                imageBase;
        size_t                   sizeOfImage;
        uint16_t                 characteristics;
        uint16_t                 dllCharacteristics;
        uint32_t                 checksum;
        uint32_t                 subsystem;
        std::string              subsystemName;
        bool                     isDLL;
        bool                     isASLR;
        bool                     isDEP;
        bool                     isCFG;
        bool                     isSEH;
        struct DataDir { uintptr_t rva; size_t size; };
        DataDir                  dataDirectories[16];
        std::vector<SectionInfo> sections;
        std::vector<ImportEntry> imports;
        std::vector<ExportEntry> exports;
        std::vector<TLSEntry>    tlsCallbacks;
    };
    PEInfo parsePE(uintptr_t moduleBase);

    // ── Cross-reference scan ─────────────────────────────────────────────────
    struct XRef {
        uintptr_t   from;
        std::string type;    // "CALL", "JMP", "LEA", "MOV", ...
        std::string context; // formatted instruction
    };

    // Find all instructions in the given buffer/range that reference `targetAddr`.
    std::vector<XRef> findXRefs(uintptr_t targetAddr,
                                uintptr_t scanBase, size_t scanLen);

    // Scan every executable region in the target process.
    std::vector<XRef> findXRefsGlobal(uintptr_t targetAddr,
                                      std::function<void(float)> progressCb = nullptr);

private:
    ProcessEngine& pe_;
    bool           dbgLoaded_ = false;

    ZydisDecoder   decoder64_;
    ZydisDecoder   decoder32_;
    ZydisFormatter formatter_;

    ZydisDecoder& activeDecoder() { return pe_.is64bit() ? decoder64_ : decoder32_; }
    ZydisMachineMode machineMode() const {
        return pe_.is64bit() ? ZYDIS_MACHINE_MODE_LONG_64
                             : ZYDIS_MACHINE_MODE_LEGACY_32;
    }

    // Resolve a branch/memory operand to its absolute target VA.
    // Returns 0 if the operand is indirect register-based and cannot be statically resolved.
    uintptr_t resolveOperandTarget(const ZydisDecodedInstruction& insn,
                                   const ZydisDecodedOperand*     ops,
                                   uintptr_t                      instrVA) const;

    // Relocate a single instruction from `srcVA` to `dstVA` when building trampolines.
    // Fills `out` with the relocated bytes. Returns false if relocation is impossible
    // (e.g. far indirect call that cannot be patched statically).
    bool relocateInstruction(const ZydisDecodedInstruction& insn,
                             const ZydisDecodedOperand*     ops,
                             uintptr_t srcVA, uintptr_t dstVA,
                             std::vector<uint8_t>& out);

    static std::string sectionCharString(DWORD ch);
    size_t safeRead(uintptr_t addr, uint8_t* buf, size_t sz) const;
};
