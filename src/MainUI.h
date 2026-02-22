#pragma once
#include "MemScanner.h"
#include "ProcessEngine.h"
#include "ScanEngine.h"
#include "DisasmEngine.h"
#include "imgui/imgui.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include <d3d11.h>
#include <dxgi.h>

// ─── MainUI ───────────────────────────────────────────────────────────────────
// Manages all ImGui windows, state machines, hotkeys
class MainUI {
public:
    MainUI();
    ~MainUI();

    bool init(HWND hwnd, ID3D11Device* device, ID3D11DeviceContext* ctx);
    void shutdown();
    void render();
    bool shouldQuit() const { return quit_; }
    void getClearColor(float out[4]) const {
        if (bgMode_ == 0) { out[0]=bgColor_[0]; out[1]=bgColor_[1]; out[2]=bgColor_[2]; out[3]=bgColor_[3]; }
        else { out[0]=0.f; out[1]=0.f; out[2]=0.f; out[3]=1.f; } // black when image bg
    }

private:
    // ── Core objects ──
    ProcessEngine  pe_;
    ScanEngine     se_;
    DisasmEngine   de_;

    // ── Scan state ──
    std::vector<ScanSession> sessions_;
    int                      activeSession_     = -1;
    ScanOptions              scanOpts_;
    char                     scanValue_[128]    = {};
    char                     scanValue2_[128]   = {};
    char                     aobPatternBuf_[512] = {};
    char                     strPatBuf_[512]    = {};
    bool                     scanning_          = false;
    std::atomic<float>       scanProgress_      { 0.f };
    ScanStats                lastStats_;
    std::string              statusMsg_;
    std::thread              scanThread_;
    std::mutex               scanMtx_;
    bool                     scanDone_          = false;

    // ── Process list ──
    std::vector<ProcessInfo> procList_;
    bool                     showProcList_      = false;
    char                     procFilter_[128]   = {};
    bool                     procListDirty_     = true;

    // ── Watch list ──
    std::vector<WatchEntry>  watchList_;
    int                      editWatchIdx_      = -1;
    char                     watchLabel_[128]   = {};
    char                     watchAddrBuf_[32]  = {};

    // ── Pointer chains ──
    std::vector<PointerChain> pointerChains_;
    int                       editChainIdx_      = -1;
    char                      chainTargetBuf_[32] = {};
    bool                      pointerScanning_   = false;
    float                     ptrScanProgress_   = 0.f;
    std::thread               ptrScanThread_;

    // ── Patches ──
    std::vector<MemPatch>     patches_;

    // ── Disasm view ──
    char                      disasmAddrBuf_[32]  = {};
    std::vector<DisasmEntry>  disasmEntries_;
    uintptr_t                 disasmBase_         = 0;
    bool                      disasmFollow_       = false;
    uintptr_t                 disasmFollowAddr_   = 0;

    // ── XRef scanner ──
    bool                      showXRef_           = false;
    char                      xrefTargetBuf_[32]  = {};
    std::vector<DisasmEngine::XRef> xrefResults_;
    bool                      xrefScanning_       = false;
    float                     xrefProgress_       = 0.f;
    std::thread               xrefThread_;

    // ── Memory view ──
    char                      memViewAddrBuf_[32] = {};
    uintptr_t                 memViewBase_        = 0;
    std::vector<uint8_t>      memViewBuf_;
    size_t                    memViewSize_        = 256;
    bool                      memViewHex_         = true;
    bool                      memViewEditing_     = false;
    int                       memViewEditOffset_  = -1;
    char                      memViewEditBuf_[8]  = {};

    // ── Region map ──
    std::vector<MemRegion>    regionMap_;
    bool                      regionMapDirty_     = true;
    int                       regionFilter_       = 0;

    // ── PE view ──
    int                       peModuleIdx_        = -1;
    DisasmEngine::PEInfo      peInfo_;
    bool                      peParsed_           = false;

    // ── Heap view ──
    std::vector<HeapBlock>    heapBlocks_;

    // ── Thread view ──
    std::vector<uint32_t>     threadIDs_;

    // ── Module view ──
    int                       selectedModule_     = -1;

    // ── Hotkeys ──
    bool                      hotkeysEnabled_     = true;

    // ── Windows toggles ──
    bool                      showScanner_        = true;
    bool                      showWatchList_      = true;
    bool                      showMemView_        = true;
    bool                      showDisasm_         = true;
    bool                      showRegionMap_      = true;
    bool                      showPEView_         = false;
    bool                      showHeapView_       = false;
    bool                      showThreadView_     = false;
    bool                      showModuleView_     = true;
    bool                      showPointerChains_  = false;
    bool                      showPatches_        = false;
    bool                      showStats_          = true;
    bool                      showSettings_       = false;
    bool                      showAbout_          = false;

    // ── Settings ──
    bool                      darkTheme_          = true;
    float                     fontSize_           = 14.f;
    int                       maxResultsDisplay_  = 2000;
    bool                      autoRefreshWatch_   = true;
    int                       refreshIntervalMs_  = 500;
    std::chrono::steady_clock::time_point lastRefresh_;


    // ── Background & Assets ──
    // Background modes: 0=solid color, 1=image
    int                       bgMode_             = 0;
    float                     bgColor_[4]         = {0.08f, 0.08f, 0.10f, 1.f};
    char                      bgImagePath_[512]   = {};
    ID3D11ShaderResourceView* bgTexture_           = nullptr;
    ID3D11Device*             d3dDevice_           = nullptr;
    int                       bgImgW_             = 0;
    int                       bgImgH_             = 0;
    float                     bgOpacity_          = 1.0f;
    bool                      bgTile_             = false;
    // Hot reload
    std::thread               assetWatchThread_;
    std::atomic<bool>         assetWatchStop_     { false };
    std::atomic<bool>         assetReloadPending_ { false };
    std::string               watchedAssetPath_;
    FILETIME                  watchedAssetMtime_  = {};
    void startAssetWatcher(const std::string& path);
    void stopAssetWatcher();
    bool loadBgTexture(const char* path);
    void freeBgTexture();
    void renderBackground();

    // ── Misc ──
    bool                      quit_               = false;
    float                     fps_                = 0.f;

    // ── Render methods ──
    void renderMenuBar();
    void renderProcessSelector();
    void renderScanner();
    void renderWatchList();
    void renderMemoryView();
    void renderDisassembler();
    void renderRegionMap();
    void renderPEView();
    void renderHeapView();
    void renderThreadView();
    void renderModuleView();
    void renderPointerChains();
    void renderPatches();
    void renderStats();
    void renderSettings();
    void renderAbout();
    void renderXRef();
    void renderStatusBar();

    // ── Helpers ──
    void startFirstScan();
    void startNextScan();
    void startAoBScan();
    void startStringScan();
    void refreshWatchList();
    void addToWatchList(const ScanResult& r);
    void refreshRegionMap();
    void jumpToAddress(uintptr_t addr);
    void refreshDisasm(uintptr_t addr);
    void refreshMemView(uintptr_t addr, size_t sz);
    void applyTheme();

    uintptr_t parseAddrStr(const char* s);
    std::string formatValue(uintptr_t addr, ValueType t);
    static ImVec4 protectColor(DWORD prot);
    static void   centerText(const char* text);

    // Async scan
    void launchScan(std::function<void()> fn);
    void pollScanDone();
};
