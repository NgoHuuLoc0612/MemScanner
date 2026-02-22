#include "MainUI.h"
#include <sstream>
#include <iomanip>

static const char* stristr_compat(const char* hay, const char* needle) {
    if (!needle || !*needle) return hay;
    for (; *hay; ++hay) {
        if (tolower((unsigned char)*hay) == tolower((unsigned char)*needle)) {
            const char *h = hay, *n = needle;
            while (*h && *n && tolower((unsigned char)*h)==tolower((unsigned char)*n)){++h;++n;}
            if (!*n) return hay;
        }
    }
    return nullptr;
}

// stb_image - single header image loader (place stb_image.h in src/)
// Download: https://github.com/nothings/stb/blob/master/stb_image.h
#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_ONLY_JPEG
#define STBI_ONLY_BMP
#include "stb_image.h"



// ─── Init / Shutdown ──────────────────────────────────────────────────────────
MainUI::MainUI() : se_(pe_), de_(pe_) {
    sessions_.push_back(ScanSession{ "Session 1" });
    activeSession_ = 0;
    scanOpts_.type      = ValueType::Int32;
    scanOpts_.condition = ScanCondition::ExactValue;
    scanOpts_.alignment = 4;
    lastRefresh_ = std::chrono::steady_clock::now();
}
MainUI::~MainUI() {
    if (scanThread_.joinable()) scanThread_.join();
    if (ptrScanThread_.joinable()) ptrScanThread_.join();
}

bool MainUI::init(HWND hwnd, ID3D11Device* device, ID3D11DeviceContext* ctx) {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();

    io.IniFilename = "memscanner.ini";
    applyTheme();
    ImGui_ImplWin32_Init(hwnd);
    d3dDevice_ = device;
    ImGui_ImplDX11_Init(device, ctx);
    return true;
}

void MainUI::shutdown() {
    stopAssetWatcher();
    freeBgTexture();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
}

// ─── Render ───────────────────────────────────────────────────────────────────
void MainUI::render() {
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    // Background render (solid color or image)
    renderBackground();

    // Fullscreen menu-bar host window (standard ImGui, no docking)
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGuiWindowFlags hostFlags =
        ImGuiWindowFlags_NoTitleBar   | ImGuiWindowFlags_NoCollapse  |
        ImGuiWindowFlags_NoResize     | ImGuiWindowFlags_NoMove      |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_MenuBar      | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBackground;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding,   0.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,    ImVec2(0.f, 0.f));
    ImGui::Begin("MemScannerHost", nullptr, hostFlags);
    ImGui::PopStyleVar(3);
    renderMenuBar();
    ImGui::End();

    pollScanDone();

    // Auto-refresh watch
    auto now = std::chrono::steady_clock::now();
    if (autoRefreshWatch_ && pe_.attached() &&
        std::chrono::duration_cast<std::chrono::milliseconds>(now - lastRefresh_).count() >= refreshIntervalMs_) {
        refreshWatchList();
        lastRefresh_ = now;
        fps_ = ImGui::GetIO().Framerate;
    }

    // Handle hotkeys
    if (hotkeysEnabled_) {
        if (ImGui::IsKeyPressed(ImGuiKey_F5) && !scanning_) startFirstScan();
        if (ImGui::IsKeyPressed(ImGuiKey_F6) && !scanning_) startNextScan();
        if (ImGui::IsKeyPressed(ImGuiKey_F12)) showSettings_ = !showSettings_;
    }

    if (showScanner_)       renderScanner();
    if (showWatchList_)     renderWatchList();
    if (showMemView_)       renderMemoryView();
    if (showDisasm_)        renderDisassembler();
    if (showRegionMap_)     renderRegionMap();
    if (showPEView_)        renderPEView();
    if (showHeapView_)      renderHeapView();
    if (showThreadView_)    renderThreadView();
    if (showModuleView_)    renderModuleView();
    if (showPointerChains_) renderPointerChains();
    if (showPatches_)       renderPatches();
    if (showXRef_)          renderXRef();
    if (showStats_)         renderStats();
    if (showSettings_)      renderSettings();
    if (showAbout_)         renderAbout();

    renderStatusBar();

    // Process selector popup — must be outside any Begin/End window
    if (showProcList_) {
        ImGui::OpenPopup("##AttachProcess");
        showProcList_ = false;
    }
    renderProcessSelector();

    ImGui::Render();

}

// ─── Menu Bar ─────────────────────────────────────────────────────────────────
void MainUI::renderMenuBar() {
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Attach Process...", "Ctrl+O")) { showProcList_ = true; procListDirty_ = true; }
            if (ImGui::MenuItem("Detach", nullptr, false, pe_.attached())) { pe_.detach(); statusMsg_ = "Detached."; }
            ImGui::Separator();
            if (ImGui::MenuItem("New Session")) {
                std::string n = "Session " + std::to_string(sessions_.size()+1);
                sessions_.push_back(ScanSession{n});
                activeSession_ = (int)sessions_.size()-1;
            }
            if (ImGui::MenuItem("Clear Active Session", nullptr, false, activeSession_ >= 0)) {
                sessions_[activeSession_].results.clear();
                sessions_[activeSession_].hasFirst = false;
                sessions_[activeSession_].scanCount = 0;
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Quit", "Alt+F4")) quit_ = true;
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Scan")) {
            if (ImGui::MenuItem("First Scan", "F5", false, pe_.attached() && !scanning_)) startFirstScan();
            if (ImGui::MenuItem("Next Scan",  "F6", false, pe_.attached() && !scanning_ && activeSession_ >= 0 && sessions_[activeSession_].hasFirst)) startNextScan();
            if (ImGui::MenuItem("AoB Scan",   nullptr, false, pe_.attached() && !scanning_)) startAoBScan();
            if (ImGui::MenuItem("String Scan",nullptr, false, pe_.attached() && !scanning_)) startStringScan();
            ImGui::Separator();
            if (ImGui::MenuItem("Cancel Scan", nullptr, false, scanning_)) se_.cancel();
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            ImGui::MenuItem("Scanner",        nullptr, &showScanner_);
            ImGui::MenuItem("Watch List",     nullptr, &showWatchList_);
            ImGui::MenuItem("Memory View",    nullptr, &showMemView_);
            ImGui::MenuItem("Disassembler",   nullptr, &showDisasm_);
            ImGui::MenuItem("Region Map",     nullptr, &showRegionMap_);
            ImGui::MenuItem("Module View",    nullptr, &showModuleView_);
            ImGui::MenuItem("PE View",        nullptr, &showPEView_);
            ImGui::MenuItem("Heap View",      nullptr, &showHeapView_);
            ImGui::MenuItem("Thread View",    nullptr, &showThreadView_);
            ImGui::MenuItem("Pointer Chains", nullptr, &showPointerChains_);
            ImGui::MenuItem("Patches",        nullptr, &showPatches_);
            ImGui::MenuItem("XRef Scanner",   nullptr, &showXRef_);
            ImGui::MenuItem("Stats",          nullptr, &showStats_);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Tools")) {
            if (ImGui::MenuItem("Pointer Scanner...", nullptr, false, pe_.attached())) {
                showPointerChains_ = true;
            }
            if (ImGui::MenuItem("Reload Symbols", nullptr, false, pe_.attached()))
                de_.loadSymbols();
            if (ImGui::MenuItem("Suspend Target", nullptr, false, pe_.attached()))
                pe_.suspend();
            if (ImGui::MenuItem("Resume Target", nullptr, false, pe_.attached()))
                pe_.resume();
            ImGui::Separator();
            if (ImGui::MenuItem("Settings", "F12")) showSettings_ = !showSettings_;
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("About")) showAbout_ = true;
            ImGui::EndMenu();
        }

        // Right-align: process name + FPS
        float rightOff = ImGui::GetContentRegionAvail().x - 320.f;
        if (rightOff > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + rightOff);
        if (pe_.attached()) {
            ImGui::TextColored({0.3f,1.f,0.3f,1.f}, "[%s  PID:%lu  %s]",
                pe_.procInfo().name.c_str(), (unsigned long)pe_.pid(), pe_.is64bit() ? "x64" : "x86");
        } else {
            ImGui::TextColored({0.7f,0.7f,0.7f,1.f}, "[No Process]");
        }
        ImGui::SameLine(0, 20);
        ImGui::TextColored({0.6f,0.9f,0.6f,0.7f}, "%.0f FPS", fps_);

        ImGui::EndMenuBar();
    }
    // Note: OpenPopupModal for AttachProcess is called from render() to avoid
    // being inside the host window context.
}

// ─── Process Selector ─────────────────────────────────────────────────────────
void MainUI::renderProcessSelector() {
    ImGui::SetNextWindowSize({600, 500}, ImGuiCond_Appearing);
    if (!ImGui::BeginPopupModal("##AttachProcess", nullptr, ImGuiWindowFlags_NoTitleBar)) return;

    ImGui::Text("Attach to Process");
    ImGui::Separator();
    ImGui::SetNextItemWidth(-1);
    if (ImGui::InputTextWithHint("##pfilt", "Filter by name...", procFilter_, sizeof(procFilter_)))
        procListDirty_ = true;

    if (ImGui::Button("Refresh")) procListDirty_ = true;
    ImGui::SameLine();
    if (ImGui::Button("Close")) ImGui::CloseCurrentPopup();

    if (procListDirty_) {
        procList_ = ProcessEngine::listProcesses();
        procListDirty_ = false;
    }

    ImGui::BeginChild("##proclist", {0,-40}, true);
    ImGui::Columns(4, "proccols");
    ImGui::SetColumnWidth(0, 60); ImGui::Text("PID");   ImGui::NextColumn();
    ImGui::SetColumnWidth(1, 200); ImGui::Text("Name"); ImGui::NextColumn();
    ImGui::SetColumnWidth(2, 60); ImGui::Text("Arch");  ImGui::NextColumn();
    ImGui::Text("Memory (WS)"); ImGui::NextColumn();
    ImGui::Separator();

    for (auto& p : procList_) {
        if (procFilter_[0] && stristr_compat(p.name.c_str(), procFilter_) == nullptr) continue;
        bool sel = false;
        char lbl[64]; snprintf(lbl, sizeof(lbl), "%lu##proc%lu", p.pid, p.pid);
        if (ImGui::Selectable(lbl, false, ImGuiSelectableFlags_SpanAllColumns)) {
            if (pe_.attach(p.pid)) {
                statusMsg_ = "Attached to " + p.name + " (PID " + std::to_string(p.pid) + ")";
                regionMapDirty_ = true;
                de_.loadSymbols();
            } else {
                statusMsg_ = "Failed to attach to PID " + std::to_string(p.pid);
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::NextColumn();
        ImGui::Text("%s", p.name.c_str()); ImGui::NextColumn();
        ImGui::Text("%s", p.is64bit ? "x64" : "x86"); ImGui::NextColumn();
        ImGui::Text("%.1f MB", p.workingSet / 1024.0 / 1024.0); ImGui::NextColumn();
    }
    ImGui::Columns(1);
    ImGui::EndChild();
    ImGui::EndPopup();
}

// ─── Scanner Window ───────────────────────────────────────────────────────────
void MainUI::renderScanner() {
    ImGui::SetNextWindowSize({700, 600}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Memory Scanner", &showScanner_);

    // Session tabs
    if (ImGui::BeginTabBar("##sessions")) {
        for (int i = 0; i < (int)sessions_.size(); ++i) {
            bool open = true;
            ImGuiTabItemFlags flags = (i == activeSession_) ? ImGuiTabItemFlags_SetSelected : 0;
            if (ImGui::BeginTabItem(sessions_[i].name.c_str(), &open, flags)) {
                if (activeSession_ != i) activeSession_ = i;
                ImGui::EndTabItem();
            }
            if (!open && sessions_.size() > 1) {
                sessions_.erase(sessions_.begin() + i);
                if (activeSession_ >= (int)sessions_.size()) activeSession_ = (int)sessions_.size()-1;
                --i;
            }
        }
        if (ImGui::TabItemButton("+")) {
            sessions_.push_back(ScanSession{"Session " + std::to_string(sessions_.size()+1)});
            activeSession_ = (int)sessions_.size()-1;
        }
        ImGui::EndTabBar();
    }

    ImGui::Separator();

    // ── Left panel: controls ──
    ImGui::BeginChild("##scancontrols", {220, 0}, true);

    // Value type
    ImGui::Text("Value Type");
    ImGui::SetNextItemWidth(-1);
    if (ImGui::BeginCombo("##vtype", ValueTypeNames[(int)scanOpts_.type])) {
        for (int i = 0; i < (int)ValueType::COUNT; ++i)
            if (ImGui::Selectable(ValueTypeNames[i], scanOpts_.type == (ValueType)i))
                scanOpts_.type = (ValueType)i;
        ImGui::EndCombo();
    }

    // Condition
    ImGui::Text("Condition");
    ImGui::SetNextItemWidth(-1);
    if (ImGui::BeginCombo("##vcond", ScanConditionNames[(int)scanOpts_.condition])) {
        for (int i = 0; i < (int)ScanCondition::COUNT; ++i)
            if (ImGui::Selectable(ScanConditionNames[i], scanOpts_.condition == (ScanCondition)i))
                scanOpts_.condition = (ScanCondition)i;
        ImGui::EndCombo();
    }

    // Value input
    bool needVal = !(scanOpts_.condition == ScanCondition::Changed ||
                     scanOpts_.condition == ScanCondition::Unchanged ||
                     scanOpts_.condition == ScanCondition::Increased ||
                     scanOpts_.condition == ScanCondition::Decreased);
    if (needVal) {
        ImGui::Text("Value");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##val", scanValue_, sizeof(scanValue_));
        if (scanOpts_.condition == ScanCondition::Between) {
            ImGui::Text("To:");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputText("##val2", scanValue2_, sizeof(scanValue2_));
        }
    }

    ImGui::Separator();
    ImGui::Text("Alignment: ");
    ImGui::SetNextItemWidth(-1);
    int align = (int)scanOpts_.alignment;
    if (ImGui::InputInt("##align", &align)) scanOpts_.alignment = std::max(1, align);

    ImGui::Checkbox("Aligned only", &scanOpts_.aligned);
    ImGui::Separator();

    // Protection filter
    ImGui::Text("Protection");
    bool r  = scanOpts_.protFilter & ProtectionFilter::Readable;
    bool w  = scanOpts_.protFilter & ProtectionFilter::Writable;
    bool x  = scanOpts_.protFilter & ProtectionFilter::Executable;
    if (ImGui::Checkbox("R", &r)) scanOpts_.protFilter = r ? (scanOpts_.protFilter | ProtectionFilter::Readable) : static_cast<ProtectionFilter>(static_cast<uint32_t>(scanOpts_.protFilter) & ~static_cast<uint32_t>(ProtectionFilter::Readable));
    ImGui::SameLine();
    if (ImGui::Checkbox("W", &w)) scanOpts_.protFilter = w ? (scanOpts_.protFilter | ProtectionFilter::Writable) : static_cast<ProtectionFilter>(static_cast<uint32_t>(scanOpts_.protFilter) & ~static_cast<uint32_t>(ProtectionFilter::Writable));
    ImGui::SameLine();
    if (ImGui::Checkbox("X", &x)) scanOpts_.protFilter = x ? (scanOpts_.protFilter | ProtectionFilter::Executable) : static_cast<ProtectionFilter>(static_cast<uint32_t>(scanOpts_.protFilter) & ~static_cast<uint32_t>(ProtectionFilter::Executable));

    ImGui::Text("Region Type");
    bool prv = scanOpts_.regionFilter & RegionTypeFilter::Private;
    bool map = scanOpts_.regionFilter & RegionTypeFilter::Mapped;
    bool img = scanOpts_.regionFilter & RegionTypeFilter::Image;
    if (ImGui::Checkbox("Private", &prv)) scanOpts_.regionFilter = prv ? (scanOpts_.regionFilter | RegionTypeFilter::Private) : static_cast<RegionTypeFilter>(static_cast<uint32_t>(scanOpts_.regionFilter) & ~static_cast<uint32_t>(RegionTypeFilter::Private));
    if (ImGui::Checkbox("Mapped",  &map)) scanOpts_.regionFilter = map ? (scanOpts_.regionFilter | RegionTypeFilter::Mapped) : static_cast<RegionTypeFilter>(static_cast<uint32_t>(scanOpts_.regionFilter) & ~static_cast<uint32_t>(RegionTypeFilter::Mapped));
    if (ImGui::Checkbox("Image",   &img)) scanOpts_.regionFilter = img ? (scanOpts_.regionFilter | RegionTypeFilter::Image) : static_cast<RegionTypeFilter>(static_cast<uint32_t>(scanOpts_.regionFilter) & ~static_cast<uint32_t>(RegionTypeFilter::Image));

    ImGui::Separator();
    ImGui::Checkbox("Pause Target", &scanOpts_.pauseTarget);
    if (scanOpts_.type == ValueType::Float)
        ImGui::InputFloat("Epsilon", &scanOpts_.floatEpsilon, 0.0001f, 0.001f, "%.6f");
    if (scanOpts_.type == ValueType::Double)
        ImGui::InputDouble("Epsilon", &scanOpts_.doubleEpsilon, 0.000001, 0.00001, "%.8f");

    ImGui::Separator();
    // AoB pattern
    if (scanOpts_.type == ValueType::AoB) {
        ImGui::Text("AoB Pattern:");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##aob", aobPatternBuf_, sizeof(aobPatternBuf_));
        ImGui::TextDisabled("e.g. AA ?? BB CC ??");
    }
    // String
    if (scanOpts_.type == ValueType::String || scanOpts_.type == ValueType::WString) {
        ImGui::Text("String:");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##str", strPatBuf_, sizeof(strPatBuf_));
        ImGui::Checkbox("Case Sensitive", &scanOpts_.strCaseSensitive);
    }

    ImGui::Separator();
    ImGui::PushStyleColor(ImGuiCol_Button, {0.1f,0.6f,0.1f,1.f});
    if (ImGui::Button("First Scan", {-1, 30}) && !scanning_ && pe_.attached())
        startFirstScan();
    ImGui::PopStyleColor();

    bool hasFirst = (activeSession_ >= 0 && sessions_[activeSession_].hasFirst);
    if (!hasFirst) ImGui::BeginDisabled();
    ImGui::PushStyleColor(ImGuiCol_Button, {0.1f,0.3f,0.8f,1.f});
    if (ImGui::Button("Next Scan", {-1, 30}) && !scanning_ && pe_.attached() && hasFirst)
        startNextScan();
    ImGui::PopStyleColor();
    if (!hasFirst) ImGui::EndDisabled();

    ImGui::PushStyleColor(ImGuiCol_Button, {0.6f,0.1f,0.1f,1.f});
    if (ImGui::Button("Reset", {-1, 0}) && activeSession_ >= 0) {
        sessions_[activeSession_].results.clear();
        sessions_[activeSession_].hasFirst = false;
        sessions_[activeSession_].scanCount = 0;
        statusMsg_ = "Session reset.";
    }
    ImGui::PopStyleColor();

    if (scanning_) {
        ImGui::Separator();
        ImGui::ProgressBar(scanProgress_, {-1, 0});
        ImGui::TextColored({1,1,0,1}, "Scanning...");
        if (ImGui::Button("Cancel")) se_.cancel();
    }
    ImGui::EndChild();
    ImGui::SameLine();

    // ── Right panel: results ──
    ImGui::BeginChild("##scanresults", {0, 0}, true);
    if (activeSession_ < 0) { ImGui::EndChild(); ImGui::End(); return; }
    ScanSession& sess = sessions_[activeSession_];

    ImGui::Text("Results: %zu  |  Scans: %zu", sess.results.size(), sess.scanCount);
    ImGui::SameLine();
    if (ImGui::SmallButton("Refresh Values") && pe_.attached())
        se_.refreshResults(sess, scanOpts_);

    ImGui::Separator();

    ImGui::Columns(4, "rescols", true);
    ImGui::SetColumnWidth(0, 160); ImGui::Text("Address");   ImGui::NextColumn();
    ImGui::SetColumnWidth(1, 120); ImGui::Text("Value");      ImGui::NextColumn();
    ImGui::SetColumnWidth(2, 120); ImGui::Text("Previous");   ImGui::NextColumn();
    ImGui::Text("Region/Module"); ImGui::NextColumn();
    ImGui::Separator();

    // Limit display
    size_t dispCount = std::min(sess.results.size(), (size_t)maxResultsDisplay_);
    ImGuiListClipper clipper;
    clipper.Begin((int)dispCount);
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            auto& res = sess.results[i];
            char addrStr[32];
            snprintf(addrStr, sizeof(addrStr), pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)res.address);
            bool sel = false;
            if (ImGui::Selectable(addrStr, sel,
                    ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(0))
                    addToWatchList(res);
            }
            if (ImGui::BeginPopupContextItem("##scanctx")) {
                if (ImGui::MenuItem("Add to Watch List")) addToWatchList(res);
                if (ImGui::MenuItem("View in Memory"))   { memViewBase_ = res.address; refreshMemView(res.address, 256); showMemView_ = true; }
                if (ImGui::MenuItem("Disassemble Here")) { disasmBase_ = res.address; refreshDisasm(res.address); showDisasm_ = true; }
                if (ImGui::MenuItem("Copy Address"))     ImGui::SetClipboardText(addrStr);
                ImGui::EndPopup();
            }
            ImGui::NextColumn();
            ImGui::Text("%s", ScanEngine::valueToString(res).c_str()); ImGui::NextColumn();
            // previous
            {
                ScanResult prev = res; prev.rawCurrent = res.rawPrevious;
                ImGui::Text("%s", ScanEngine::valueToString(prev).c_str());
            }
            ImGui::NextColumn();
            ImGui::Text("%s", res.regionModule.empty() ? "-" : res.regionModule.c_str());
            ImGui::NextColumn();
        }
    }
    clipper.End();
    ImGui::Columns(1);

    if (sess.results.size() > (size_t)maxResultsDisplay_)
        ImGui::TextColored({1,0.5f,0,1}, "Showing %d of %zu results", maxResultsDisplay_, sess.results.size());

    ImGui::EndChild();
    ImGui::End();
}

// ─── Watch List ───────────────────────────────────────────────────────────────
void MainUI::renderWatchList() {
    ImGui::SetNextWindowSize({700, 300}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Watch List", &showWatchList_);

    if (ImGui::Button("Add Entry")) {
        WatchEntry e;
        e.label   = "New Entry";
        e.address = 0;
        e.type    = ValueType::Int32;
        watchList_.push_back(e);
        editWatchIdx_ = (int)watchList_.size()-1;
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh All") && pe_.attached()) refreshWatchList();
    ImGui::SameLine();
    ImGui::Checkbox("Auto Refresh", &autoRefreshWatch_);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80);
    ImGui::InputInt("ms", &refreshIntervalMs_);

    ImGui::Separator();
    ImGui::Columns(7, "watchcols", true);
    ImGui::Text("Label");    ImGui::NextColumn();
    ImGui::Text("Address");  ImGui::NextColumn();
    ImGui::Text("Type");     ImGui::NextColumn();
    ImGui::Text("Value");    ImGui::NextColumn();
    ImGui::Text("Frozen");   ImGui::NextColumn();
    ImGui::Text("Graph");    ImGui::NextColumn();
    ImGui::Text("Actions");  ImGui::NextColumn();
    ImGui::Separator();

    for (int i = 0; i < (int)watchList_.size(); ++i) {
        auto& e = watchList_[i];
        ImGui::PushID(i);

        // Live value
        uint64_t liveVal = 0;
        bool readOk = false;
        size_t tsz = ValueTypeSizes[(int)e.type];
        if (pe_.attached() && tsz > 0)
            readOk = pe_.readBytes(e.address, &liveVal, tsz);

        ImGui::TextColored(e.highlight ? ImVec4(1,1,0,1) : ImVec4(1,1,1,1), "%s", e.label.c_str());
        ImGui::NextColumn();

        char addrStr[32];
        snprintf(addrStr, sizeof(addrStr), pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)e.address);
        ImGui::Text("%s", addrStr);
        ImGui::NextColumn();
        ImGui::Text("%s", ValueTypeNames[(int)e.type]);
        ImGui::NextColumn();

        // Value + editable
        if (e.frozen) {
            liveVal = e.frozenValue;
            readOk  = true;
        }
        if (readOk) {
            ScanResult fakeR; fakeR.type = e.type; fakeR.rawCurrent = liveVal;
            std::string valStr = ScanEngine::valueToString(fakeR);
            ImGui::SetNextItemWidth(100);
            char valBuf[64]; strncpy(valBuf, valStr.c_str(), sizeof(valBuf)-1); valBuf[sizeof(valBuf)-1]=0;
            if (ImGui::InputText("##val", valBuf, sizeof(valBuf), ImGuiInputTextFlags_EnterReturnsTrue)) {
                // write new value
                uint64_t nv = 0;
                if (e.type == ValueType::Float) { float f = strtof(valBuf,0); memcpy(&nv,&f,4); }
                else if (e.type == ValueType::Double) { double d = strtod(valBuf,0); memcpy(&nv,&d,8); }
                else nv = strtoull(valBuf, 0, 10);
                pe_.writeBytes(e.address, &nv, tsz);
                if (e.frozen) e.frozenValue = nv;
            }
            // Push to history
            float fv = 0;
            if (e.type == ValueType::Float) { float f; memcpy(&f,&liveVal,4); fv=f; }
            else fv = (float)(int64_t)liveVal;
            e.pushHistory(fv);
        } else {
            ImGui::TextDisabled("???");
        }
        ImGui::NextColumn();

        // Freeze toggle
        if (ImGui::Checkbox("##frz", &e.frozen)) {
            if (e.frozen) e.frozenValue = liveVal;
        }
        if (e.frozen && pe_.attached() && tsz > 0)
            pe_.writeBytes(e.address, &e.frozenValue, tsz);
        ImGui::NextColumn();

        // Mini sparkline
        if (e.histCount > 1) {
            float minV = *std::min_element(e.history, e.history + e.histCount);
            float maxV = *std::max_element(e.history, e.history + e.histCount);
            if (minV == maxV) { minV -= 1; maxV += 1; }
            ImGui::PlotLines("##hist", e.history, e.histCount, e.histHead,
                             nullptr, minV, maxV, {120, 30});
        } else {
            ImGui::TextDisabled("-");
        }
        ImGui::NextColumn();

        if (ImGui::SmallButton("M")) { refreshMemView(e.address, 256); showMemView_ = true; }
        ImGui::SameLine();
        if (ImGui::SmallButton("D")) { refreshDisasm(e.address); showDisasm_ = true; }
        ImGui::SameLine();
        if (ImGui::SmallButton("X")) { watchList_.erase(watchList_.begin() + i); --i; }
        ImGui::NextColumn();

        ImGui::PopID();
    }
    ImGui::Columns(1);
    ImGui::End();
}

// ─── Memory View ──────────────────────────────────────────────────────────────
void MainUI::renderMemoryView() {
    ImGui::SetNextWindowSize({700, 350}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Memory View", &showMemView_);

    ImGui::SetNextItemWidth(200);
    if (ImGui::InputText("Address##mv", memViewAddrBuf_, sizeof(memViewAddrBuf_),
            ImGuiInputTextFlags_EnterReturnsTrue)) {
        uintptr_t a = parseAddrStr(memViewAddrBuf_);
        if (a) { memViewBase_ = a; refreshMemView(a, memViewSize_); }
    }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(100);
    int sz = (int)memViewSize_;
    if (ImGui::InputInt("Bytes##mv", &sz)) {
        memViewSize_ = std::max(16, std::min(sz, 65536));
        if (memViewBase_) refreshMemView(memViewBase_, memViewSize_);
    }
    ImGui::SameLine();
    if (ImGui::Button("Go") && memViewBase_) refreshMemView(memViewBase_, memViewSize_);
    ImGui::SameLine();
    if (ImGui::Button("-256") && memViewBase_ > 256) {
        memViewBase_ -= 256;
        refreshMemView(memViewBase_, memViewSize_);
        snprintf(memViewAddrBuf_, sizeof(memViewAddrBuf_), pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)memViewBase_);
    }
    ImGui::SameLine();
    if (ImGui::Button("+256")) {
        memViewBase_ += 256;
        refreshMemView(memViewBase_, memViewSize_);
        snprintf(memViewAddrBuf_, sizeof(memViewAddrBuf_), pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)memViewBase_);
    }

    ImGui::Checkbox("Live Hex Edit", &memViewEditing_);

    ImGui::BeginChild("##memhex", {0,0}, true, ImGuiWindowFlags_HorizontalScrollbar);
    const int COLS = 16;
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts.Size > 1 ? ImGui::GetIO().Fonts->Fonts[1] : nullptr); // monospace

    for (size_t row = 0; row < memViewBuf_.size(); row += COLS) {
        ImGui::PushID((int)row);
        uintptr_t rowAddr = memViewBase_ + row;
        // Address
        if (pe_.is64bit())
            ImGui::Text("%016llX  ", (unsigned long long)rowAddr);
        else
            ImGui::Text("%08X  ", (unsigned int)rowAddr);
        ImGui::SameLine();

        // Hex bytes
        for (int col = 0; col < COLS; ++col) {
            if (row + col >= memViewBuf_.size()) { ImGui::SameLine(); ImGui::TextDisabled("   "); continue; }
            ImGui::SameLine();
            uint8_t b = memViewBuf_[row+col];
            if (memViewEditing_) {
                char hbuf[4]; snprintf(hbuf, sizeof(hbuf), "%02X", b);
                ImGui::SetNextItemWidth(26);
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, {1,1});
                if (ImGui::InputText(("##hb"+std::to_string(row+col)).c_str(), hbuf, sizeof(hbuf),
                        ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_EnterReturnsTrue)) {
                    uint8_t nv = (uint8_t)strtoul(hbuf, 0, 16);
                    pe_.writeBytes(rowAddr+col, &nv, 1);
                    memViewBuf_[row+col] = nv;
                }
                ImGui::PopStyleVar();
            } else {
                if (b == 0)         ImGui::TextDisabled("%02X", b);
                else if (b < 0x20)  ImGui::TextColored({0.5f,0.5f,1,1}, "%02X", b);
                else if (b >= 0x80) ImGui::TextColored({1,0.8f,0.2f,1}, "%02X", b);
                else                ImGui::Text("%02X", b);
            }
            if (col == 7) ImGui::SameLine(), ImGui::TextDisabled(" ");
        }
        // ASCII
        ImGui::SameLine();
        ImGui::TextDisabled("  |");
        ImGui::SameLine();
        for (int col = 0; col < COLS && row+col < memViewBuf_.size(); ++col) {
            uint8_t c = memViewBuf_[row+col];
            char ch = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
            char s[2] = {ch, 0};
            ImGui::SameLine(0,0);
            ImGui::Text("%s", s);
        }
        ImGui::PopID();
    }

    ImGui::PopFont();
    ImGui::EndChild();
    ImGui::End();
}

// ─── Disassembler ─────────────────────────────────────────────────────────────
void MainUI::renderDisassembler() {
    ImGui::SetNextWindowSize({700, 500}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Disassembler", &showDisasm_);

    ImGui::SetNextItemWidth(200);
    if (ImGui::InputText("Address##da", disasmAddrBuf_, sizeof(disasmAddrBuf_),
            ImGuiInputTextFlags_EnterReturnsTrue)) {
        uintptr_t a = parseAddrStr(disasmAddrBuf_);
        if (a) { disasmBase_ = a; refreshDisasm(a); }
    }
    ImGui::SameLine();
    if (ImGui::Button("Go##da")) {
        uintptr_t a = parseAddrStr(disasmAddrBuf_);
        if (a) { disasmBase_ = a; refreshDisasm(a); }
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh##da") && disasmBase_) refreshDisasm(disasmBase_);
    ImGui::SameLine();
    ImGui::Checkbox("Follow jumps", &disasmFollow_);
    ImGui::SameLine();
    if (ImGui::Button("Find XRefs") && disasmBase_) {
        snprintf(xrefTargetBuf_, sizeof(xrefTargetBuf_),
                 pe_.is64bit() ? "%016llX" : "%08llX",
                 (unsigned long long)disasmBase_);
        showXRef_ = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Trace JMP chain") && disasmBase_) {
        auto chain = de_.traceJmpChain(disasmBase_, 16);
        if (!chain.empty()) {
            uintptr_t final_ = chain.back();
            refreshDisasm(final_);
            disasmBase_ = final_;
            snprintf(disasmAddrBuf_, sizeof(disasmAddrBuf_),
                     pe_.is64bit() ? "%016llX" : "%08llX",
                     (unsigned long long)final_);
            statusMsg_ = "JMP chain depth=" + std::to_string(chain.size()) +
                         " final=" + disasmAddrBuf_;
        }
    }

    ImGui::Separator();
    ImGui::Columns(4, "dasmcols", true);
    ImGui::SetColumnWidth(0, 160); ImGui::Text("Address");   ImGui::NextColumn();
    ImGui::SetColumnWidth(1, 180); ImGui::Text("Bytes");     ImGui::NextColumn();
    ImGui::SetColumnWidth(2, 100); ImGui::Text("Mnemonic");  ImGui::NextColumn();
    ImGui::Text("Operands"); ImGui::NextColumn();
    ImGui::Separator();

    static int selectedInsn = -1;
    for (int i = 0; i < (int)disasmEntries_.size(); ++i) {
        auto& e = disasmEntries_[i];
        ImGui::PushID(i);
        char addrStr[32];
        snprintf(addrStr, sizeof(addrStr), pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)e.address);

        ImVec4 mnmColor = {1,1,1,1};
        if (e.isCall) mnmColor = {1.0f,0.8f,0.0f,1.f};
        else if (e.isJump) mnmColor = {0.4f,0.8f,1.0f,1.f};
        else if (e.isRet)  mnmColor = {1.0f,0.4f,0.4f,1.f};

        bool sel = (selectedInsn == i);
        if (ImGui::Selectable(addrStr, sel,
                ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
            selectedInsn = i;
            if (ImGui::IsMouseDoubleClicked(0) && (e.isJump || e.isCall)) {
                // Try to parse target
                size_t pos = e.operands.find("0x");
                if (pos != std::string::npos) {
                    uintptr_t tgt = (uintptr_t)strtoull(e.operands.c_str()+pos+2, 0, 16);
                    refreshDisasm(tgt);
                    disasmBase_ = tgt;
                    snprintf(disasmAddrBuf_, sizeof(disasmAddrBuf_),
                             pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)tgt);
                }
            }
        }
        if (ImGui::BeginPopupContextItem("##disctx")) {
            if (ImGui::MenuItem("NOP this instruction")) {
                MemPatch p;
                if (de_.nopRange(e.address, e.length, p)) {
                    de_.applyPatch(p);
                    patches_.push_back(p);
                    refreshDisasm(disasmBase_);
                }
            }
            if (ImGui::MenuItem("Add Breakpoint (conceptual)"))
                statusMsg_ = "BP added at " + std::string(addrStr) + " (use debugger API)";
            if (ImGui::MenuItem("View in Memory")) {
                memViewBase_ = e.address;
                refreshMemView(e.address, 256);
                showMemView_ = true;
            }
            if (ImGui::MenuItem("Copy Address")) ImGui::SetClipboardText(addrStr);
            ImGui::EndPopup();
        }
        ImGui::NextColumn();
        ImGui::TextDisabled("%s", e.bytes.c_str()); ImGui::NextColumn();
        ImGui::TextColored(mnmColor, "%s", e.mnemonic.c_str()); ImGui::NextColumn();
        ImGui::Text("%s", e.operands.c_str()); ImGui::NextColumn();
        ImGui::PopID();
    }
    ImGui::Columns(1);

    ImGui::End();
}

// ─── Region Map ───────────────────────────────────────────────────────────────
void MainUI::renderRegionMap() {
    ImGui::SetNextWindowSize({800, 500}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Memory Region Map", &showRegionMap_);

    if (ImGui::Button("Refresh") || regionMapDirty_) {
        if (pe_.attached()) {
            regionMap_ = pe_.queryRegions(ProtectionFilter::All, RegionTypeFilter::All);
            regionMapDirty_ = false;
        }
    }
    ImGui::SameLine();
    ImGui::Text("%zu regions", regionMap_.size());
    ImGui::SameLine();
    uint64_t total = 0;
    for (auto& r : regionMap_) total += r.size;
    ImGui::Text("(%.1f MB total committed)", total / 1024.0 / 1024.0);

    ImGui::Separator();
    ImGui::Columns(6, "regcols", true);
    ImGui::SetColumnWidth(0, 160); ImGui::Text("Base");       ImGui::NextColumn();
    ImGui::SetColumnWidth(1, 100); ImGui::Text("Size");       ImGui::NextColumn();
    ImGui::SetColumnWidth(2, 60);  ImGui::Text("Prot");       ImGui::NextColumn();
    ImGui::SetColumnWidth(3, 50);  ImGui::Text("Type");       ImGui::NextColumn();
    ImGui::SetColumnWidth(4, 80);  ImGui::Text("State");      ImGui::NextColumn();
    ImGui::Text("Module"); ImGui::NextColumn();
    ImGui::Separator();

    ImGuiListClipper clipper;
    clipper.Begin((int)regionMap_.size());
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            auto& reg = regionMap_[i];
            ImGui::PushID(i);
            char baseStr[32];
            snprintf(baseStr, sizeof(baseStr), pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)reg.base);

            ImVec4 color = protectColor(reg.protect);
            ImGui::TextColored(color, "%s", baseStr);
            if (ImGui::BeginPopupContextItem("##regctx")) {
                if (ImGui::MenuItem("View in Memory")) { memViewBase_ = reg.base; refreshMemView(reg.base, 256); showMemView_ = true; }
                if (ImGui::MenuItem("Disassemble"))    { disasmBase_ = reg.base; refreshDisasm(reg.base); showDisasm_ = true; }
                ImGui::EndPopup();
            }
            ImGui::NextColumn();
            if (reg.size >= 1024*1024) ImGui::Text("%.1f MB", reg.size/1024.0/1024.0);
            else ImGui::Text("%.1f KB", reg.size/1024.0);
            ImGui::NextColumn();
            ImGui::TextColored(color, "%s", reg.protectString().c_str()); ImGui::NextColumn();
            ImGui::Text("%s", reg.typeString().c_str()); ImGui::NextColumn();
            ImGui::Text("%s", reg.state==MEM_COMMIT?"COM":reg.state==MEM_RESERVE?"RES":"FREE"); ImGui::NextColumn();
            ImGui::Text("%s", reg.moduleName.empty() ? "-" : reg.moduleName.c_str()); ImGui::NextColumn();
            ImGui::PopID();
        }
    }
    clipper.End();
    ImGui::Columns(1);
    ImGui::End();
}

// ─── Module View ──────────────────────────────────────────────────────────────
void MainUI::renderModuleView() {
    ImGui::SetNextWindowSize({700, 400}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Modules", &showModuleView_);

    if (ImGui::Button("Refresh")) pe_.refreshModules();

    ImGui::Columns(4, "modcols", true);
    ImGui::SetColumnWidth(0, 200); ImGui::Text("Name");    ImGui::NextColumn();
    ImGui::SetColumnWidth(1, 160); ImGui::Text("Base");    ImGui::NextColumn();
    ImGui::SetColumnWidth(2, 80);  ImGui::Text("Size");    ImGui::NextColumn();
    ImGui::Text("Path"); ImGui::NextColumn();
    ImGui::Separator();

    auto& mods = pe_.procInfo().modules;
    for (int i = 0; i < (int)mods.size(); ++i) {
        auto& m = mods[i];
        ImGui::PushID(i);
        bool sel = (selectedModule_ == i);
        if (ImGui::Selectable(m.name.c_str(), sel, ImGuiSelectableFlags_SpanAllColumns)) selectedModule_ = i;
        if (ImGui::BeginPopupContextItem("##modctx")) {
            if (ImGui::MenuItem("Parse PE")) {
                peInfo_   = de_.parsePE(m.base);
                peParsed_ = true;
                showPEView_ = true;
            }
            if (ImGui::MenuItem("Disassemble EP") && peParsed_) {
                refreshDisasm(peInfo_.entryPoint);
                disasmBase_ = peInfo_.entryPoint;
                showDisasm_  = true;
            }
            if (ImGui::MenuItem("View in Memory")) {
                memViewBase_ = m.base;
                refreshMemView(m.base, 256);
                showMemView_ = true;
            }
            ImGui::EndPopup();
        }
        ImGui::NextColumn();
        char baseStr[32]; snprintf(baseStr, sizeof(baseStr), pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)m.base);
        ImGui::Text("%s", baseStr); ImGui::NextColumn();
        ImGui::Text("%.1f KB", m.size/1024.0); ImGui::NextColumn();
        ImGui::TextDisabled("%s", m.path.c_str()); ImGui::NextColumn();
        ImGui::PopID();
    }
    ImGui::Columns(1);
    ImGui::End();
}

// ─── PE View ─────────────────────────────────────────────────────────────────
void MainUI::renderPEView() {
    ImGui::SetNextWindowSize({700, 500}, ImGuiCond_FirstUseEver);
    ImGui::Begin("PE Analyzer", &showPEView_);
    if (!peParsed_) { ImGui::Text("No PE parsed yet. Right-click a module → Parse PE."); ImGui::End(); return; }
    auto& pe = peInfo_;
    ImGui::Text("Arch: %s  |  Image Base: 0x%llX  |  Entry: 0x%llX  |  Size: %.1f KB",
        pe.arch.c_str(), (unsigned long long)pe.imageBase,
        (unsigned long long)pe.entryPoint, pe.sizeOfImage/1024.0);
    ImGui::Separator();
    if (ImGui::BeginTabBar("##petabs")) {
        if (ImGui::BeginTabItem("Sections")) {
            ImGui::Columns(4,"secs");
            ImGui::Text("Name"); ImGui::NextColumn(); ImGui::Text("RVA"); ImGui::NextColumn();
            ImGui::Text("Size"); ImGui::NextColumn(); ImGui::Text("Chars"); ImGui::NextColumn();
            ImGui::Separator();
            for (auto& s : pe.sections) {
                ImGui::Text("%s", s.name.c_str()); ImGui::NextColumn();
                ImGui::Text("%08X", (unsigned)s.rva); ImGui::NextColumn();
                ImGui::Text("%.1f KB", s.virtualSize/1024.0); ImGui::NextColumn();
                char cflags[64]="";
                if (s.characteristics & 0x20) strcat(cflags,"CODE ");
                if (s.characteristics & 0x40) strcat(cflags,"DATA ");
                if (s.characteristics & 0x80) strcat(cflags,"BSSD ");
                if (s.characteristics & 0x20000000) strcat(cflags,"EXEC ");
                if (s.characteristics & 0x40000000) strcat(cflags,"READ ");
                if (s.characteristics & 0x80000000) strcat(cflags,"WRIT ");
                ImGui::Text("%s", cflags); ImGui::NextColumn();
            }
            ImGui::Columns(1);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Imports")) {
            for (auto& imp : pe.imports) {
                if (ImGui::TreeNode(imp.dll.c_str())) {
                    for (auto& fn : imp.funcs) ImGui::TextDisabled("  %s", fn.name.c_str());
                    ImGui::TreePop();
                }
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Exports")) {
            ImGui::Columns(3,"expcols");
            ImGui::Text("Ordinal"); ImGui::NextColumn();
            ImGui::Text("RVA");     ImGui::NextColumn();
            ImGui::Text("Name");    ImGui::NextColumn();
            ImGui::Separator();
            ImGuiListClipper clip;
            clip.Begin((int)pe.exports.size());
            while (clip.Step()) {
                for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                    auto& ex = pe.exports[i];
                    ImGui::Text("%u", (unsigned)ex.ordinal); ImGui::NextColumn();
                    ImGui::Text("%08X", (unsigned)ex.rva);   ImGui::NextColumn();
                    ImGui::Text("%s", ex.name.c_str());      ImGui::NextColumn();
                }
            }
            clip.End();
            ImGui::Columns(1);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

// ─── Heap View ────────────────────────────────────────────────────────────────
void MainUI::renderHeapView() {
    ImGui::SetNextWindowSize({600, 400}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Heap View", &showHeapView_);
    if (ImGui::Button("Scan Heap Blocks") && pe_.attached()) {
        heapBlocks_ = pe_.getHeapBlocks();
        statusMsg_ = "Heap scan: " + std::to_string(heapBlocks_.size()) + " blocks";
    }
    ImGui::Text("%zu heap blocks", heapBlocks_.size());
    ImGui::Separator();
    ImGui::Columns(4,"hcols");
    ImGui::Text("Address"); ImGui::NextColumn();
    ImGui::Text("Size");    ImGui::NextColumn();
    ImGui::Text("State");   ImGui::NextColumn();
    ImGui::Text("Flags");   ImGui::NextColumn();
    ImGui::Separator();
    ImGuiListClipper clip;
    clip.Begin((int)std::min(heapBlocks_.size(),(size_t)5000));
    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
            auto& b = heapBlocks_[i];
            ImGui::PushID(i);
            char as[32]; snprintf(as,sizeof(as), pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)b.address);
            if (ImGui::Selectable(as,false,ImGuiSelectableFlags_SpanAllColumns)) {
                memViewBase_ = b.address;
                refreshMemView(b.address, std::min(b.size,(size_t)512));
                showMemView_ = true;
            }
            ImGui::NextColumn();
            ImGui::Text("%.1f KB", b.size/1024.0); ImGui::NextColumn();
            ImGui::Text("%s", b.isBusy ? "Busy" : "Free"); ImGui::NextColumn();
            ImGui::Text("%08lX", b.flags); ImGui::NextColumn();
            ImGui::PopID();
        }
    }
    clip.End();
    ImGui::Columns(1);
    ImGui::End();
}

// ─── Thread View ─────────────────────────────────────────────────────────────
void MainUI::renderThreadView() {
    ImGui::SetNextWindowSize({400, 300}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Threads", &showThreadView_);
    if (ImGui::Button("Refresh") && pe_.attached())
        threadIDs_ = pe_.getThreadIDs();
    ImGui::Text("%zu threads", threadIDs_.size());
    ImGui::Separator();
    for (auto tid : threadIDs_) {
        ImGui::PushID((int)tid);
        ImGui::Text("TID: %u", tid);
        ImGui::SameLine(150);
        if (ImGui::SmallButton("Suspend")) {
            HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
            if (t) { SuspendThread(t); CloseHandle(t); }
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Resume")) {
            HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
            if (t) { ResumeThread(t); CloseHandle(t); }
        }
        ImGui::PopID();
    }
    ImGui::End();
}

// ─── Pointer Chains ──────────────────────────────────────────────────────────
void MainUI::renderPointerChains() {
    ImGui::SetNextWindowSize({700, 400}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Pointer Scanner", &showPointerChains_);

    ImGui::Text("Target Address:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200);
    ImGui::InputText("##ptgt", chainTargetBuf_, sizeof(chainTargetBuf_));
    ImGui::SameLine();
    if (!pointerScanning_) {
        if (ImGui::Button("Scan") && pe_.attached()) {
            uintptr_t tgt = parseAddrStr(chainTargetBuf_);
            if (tgt) {
                pointerScanning_ = true;
                ptrScanProgress_ = 0.f;
                if (ptrScanThread_.joinable()) ptrScanThread_.join();
                ptrScanThread_ = std::thread([this, tgt] {
                    se_.pointerScan(tgt, 4, 0x1000, pointerChains_,
                        [this](float p){ ptrScanProgress_ = p; });
                    pointerScanning_ = false;
                });
            }
        }
    } else {
        if (ImGui::Button("Cancel")) { /* no cancel yet */ }
        ImGui::SameLine();
        ImGui::ProgressBar(ptrScanProgress_, {200,0});
    }

    ImGui::Text("%zu chains found", pointerChains_.size());
    ImGui::Separator();
    ImGui::Columns(4,"ptrcols");
    ImGui::Text("Name/Module"); ImGui::NextColumn();
    ImGui::Text("Base Offset"); ImGui::NextColumn();
    ImGui::Text("Offsets");     ImGui::NextColumn();
    ImGui::Text("Actions");     ImGui::NextColumn();
    ImGui::Separator();

    for (int i = 0; i < (int)std::min(pointerChains_.size(),(size_t)500); ++i) {
        auto& c = pointerChains_[i];
        ImGui::PushID(i);
        ImGui::Text("%s", c.name.c_str()); ImGui::NextColumn();
        ImGui::Text("%08llX", (unsigned long long)c.baseOffset); ImGui::NextColumn();
        for (auto off : c.offsets) { ImGui::SameLine(0,4); ImGui::Text("%+lldh", (long long)(ptrdiff_t)off); }
        ImGui::NextColumn();
        if (ImGui::SmallButton("Watch")) {
            uintptr_t resolved = pe_.resolvePointerChain(c);
            if (resolved) {
                WatchEntry w;
                w.label   = c.name;
                w.address = resolved;
                w.type    = c.type;
                watchList_.push_back(w);
                statusMsg_ = "Added pointer chain to watch: " + c.name;
            }
        }
        ImGui::NextColumn();
        ImGui::PopID();
    }
    ImGui::Columns(1);
    ImGui::End();
}

// ─── Patches ─────────────────────────────────────────────────────────────────
void MainUI::renderPatches() {
    ImGui::SetNextWindowSize({600, 300}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Patches", &showPatches_);

    ImGui::Columns(5,"patchcols");
    ImGui::Text("Name");    ImGui::NextColumn();
    ImGui::Text("Address"); ImGui::NextColumn();
    ImGui::Text("Size");    ImGui::NextColumn();
    ImGui::Text("Applied"); ImGui::NextColumn();
    ImGui::Text("Actions"); ImGui::NextColumn();
    ImGui::Separator();

    for (int i = 0; i < (int)patches_.size(); ++i) {
        auto& p = patches_[i];
        ImGui::PushID(i);
        ImGui::Text("%s", p.name.c_str()); ImGui::NextColumn();
        char as[32]; snprintf(as,sizeof(as), pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)p.address);
        ImGui::Text("%s", as); ImGui::NextColumn();
        ImGui::Text("%zu", p.patchedBytes.size()); ImGui::NextColumn();
        ImGui::TextColored(p.applied ? ImVec4(0,1,0,1) : ImVec4(1,0,0,1), "%s", p.applied ? "YES" : "NO");
        ImGui::NextColumn();
        if (p.applied) {
            if (ImGui::SmallButton("Revert")) de_.revertPatch(p);
        } else {
            if (ImGui::SmallButton("Apply")) de_.applyPatch(p);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Delete")) { patches_.erase(patches_.begin()+i); --i; }
        ImGui::NextColumn();
        ImGui::PopID();
    }
    ImGui::Columns(1);
    ImGui::End();
}

// ─── Stats ────────────────────────────────────────────────────────────────────
void MainUI::renderStats() {
    ImGui::SetNextWindowSize({300, 160}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Scan Stats", &showStats_);
    ImGui::Text("Regions Scanned: %zu", lastStats_.regionsScanned);
    ImGui::Text("Bytes Scanned:   %.1f MB", lastStats_.bytesScanned/1024.0/1024.0);
    ImGui::Text("Results Found:   %zu", lastStats_.resultsFound);
    ImGui::Text("Elapsed:         %.1f ms", lastStats_.elapsedMs);
    ImGui::Text("Throughput:      %.1f MB/s", lastStats_.throughputMBs);
    if (lastStats_.wasTruncated)
        ImGui::TextColored({1,0.5f,0,1}, "TRUNCATED (limit hit)");
    ImGui::End();
}

// ─── Settings ────────────────────────────────────────────────────────────────
void MainUI::renderSettings() {
    ImGui::SetNextWindowSize({520, 400}, ImGuiCond_FirstUseEver);
    ImGui::Begin("Settings", &showSettings_);

    if (ImGui::BeginTabBar("##settabs")) {

        // ── General ──
        if (ImGui::BeginTabItem("General")) {
            if (ImGui::Checkbox("Dark Theme", &darkTheme_)) applyTheme();
            ImGui::InputInt("Max Results Display", &maxResultsDisplay_);
            ImGui::Checkbox("Auto-Refresh Watch",  &autoRefreshWatch_);
            ImGui::InputInt("Refresh Interval (ms)", &refreshIntervalMs_);
            ImGui::Checkbox("Enable Hotkeys", &hotkeysEnabled_);
            ImGui::Separator();
            ImGui::TextDisabled("F5 = First Scan  F6 = Next Scan  F12 = Settings");
            ImGui::TextDisabled("Double-click result = add to Watch");
            ImGui::TextDisabled("Right-click = context menu");
            ImGui::EndTabItem();
        }

        // ── Background ──
        if (ImGui::BeginTabItem("Background")) {
            ImGui::Text("Mode:");
            ImGui::RadioButton("Solid Color", &bgMode_, 0); ImGui::SameLine();
            ImGui::RadioButton("Image",       &bgMode_, 1);
            ImGui::Spacing();

            if (bgMode_ == 0) {
                ImGui::Text("Background Color:");
                ImGui::ColorEdit4("##bgcol", bgColor_,
                    ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_PickerHueWheel);
            } else {
                ImGui::Text("Image Path (PNG / JPG / BMP):");
                ImGui::SetNextItemWidth(-110.f);
                ImGui::InputText("##bgpath", bgImagePath_, sizeof(bgImagePath_));
                ImGui::SameLine();
                if (ImGui::Button("Load##bg")) {
                    if (loadBgTexture(bgImagePath_)) {
                        startAssetWatcher(bgImagePath_);
                        statusMsg_ = "Background loaded.";
                    } else {
                        statusMsg_ = "Failed to load image!";
                    }
                }
                ImGui::Spacing();
                ImGui::SliderFloat("Opacity##bg", &bgOpacity_, 0.0f, 1.0f);
                ImGui::Checkbox("Tile image",  &bgTile_);
                ImGui::Spacing();
                if (bgTexture_) {
                    ImGui::TextColored({0.3f,1.f,0.3f,1.f},
                        "Loaded: %dx%d", bgImgW_, bgImgH_);
                    // Hot reload
                    if (assetReloadPending_) {
                        assetReloadPending_ = false;
                        loadBgTexture(bgImagePath_);
                        statusMsg_ = "Background hot-reloaded.";
                    }
                    ImGui::TextDisabled("Hot reload: watching for file changes (500ms)");
                    if (ImGui::Button("Clear Image")) {
                        freeBgTexture();
                        stopAssetWatcher();
                        bgMode_ = 0;
                    }
                } else {
                    ImGui::TextDisabled("No image loaded");
                }
            }
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }
    ImGui::End();
}

// ─── About ────────────────────────────────────────────────────────────────────
void MainUI::renderAbout() {
    ImGui::SetNextWindowSize({400, 200}, ImGuiCond_Appearing);
    ImGui::Begin("About MemScanner", &showAbout_);
    ImGui::Text("MemScanner - Enterprise Memory Analysis Tool");
    ImGui::TextDisabled("Built with ImGui + DirectX 11 + WinAPI");
    ImGui::TextDisabled("MinGW64 / GCC");
    ImGui::Separator();
    ImGui::TextWrapped("Features: Multi-threaded scan, AoB/String/Pointer scan, "
        "Disassembler, PE parser, Memory editor, Heap viewer, Patch manager, "
        "Watch list with sparklines, Value freeze, Thread control.");
    ImGui::End();
}


// ─── Background Rendering ─────────────────────────────────────────────────────
void MainUI::renderBackground() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImDrawList* dl = ImGui::GetBackgroundDrawList();

    if (bgMode_ == 0 || !bgTexture_) {
        // Solid color fill
        ImU32 col = ImGui::ColorConvertFloat4ToU32(ImVec4(bgColor_[0],bgColor_[1],bgColor_[2],bgColor_[3]));
        dl->AddRectFilled(vp->WorkPos,
            ImVec2(vp->WorkPos.x + vp->WorkSize.x, vp->WorkPos.y + vp->WorkSize.y), col);
    } else {
        // Image background
        ImU32 tint = IM_COL32(255,255,255,(int)(bgOpacity_ * 255));
        float iw = (float)bgImgW_, ih = (float)bgImgH_;
        float sw = vp->WorkSize.x,  sh = vp->WorkSize.y;
        if (bgTile_) {
            // Tile the image
            for (float y = vp->WorkPos.y; y < vp->WorkPos.y + sh; y += ih)
                for (float x = vp->WorkPos.x; x < vp->WorkPos.x + sw; x += iw)
                    dl->AddImage((ImTextureID)bgTexture_,
                        ImVec2(x, y), ImVec2(x + iw, y + ih), ImVec2(0,0), ImVec2(1,1), tint);
        } else {
            // Stretch to fill
            dl->AddImage((ImTextureID)bgTexture_, vp->WorkPos,
                ImVec2(vp->WorkPos.x + sw, vp->WorkPos.y + sh),
                ImVec2(0,0), ImVec2(1,1), tint);
        }
    }
}

bool MainUI::loadBgTexture(const char* path) {
    freeBgTexture();
    if (!d3dDevice_ || !path || !path[0]) return false;

    int w, h, ch;
    unsigned char* data = stbi_load(path, &w, &h, &ch, 4);
    if (!data) return false;

    D3D11_TEXTURE2D_DESC desc{};
    desc.Width            = (UINT)w;
    desc.Height           = (UINT)h;
    desc.MipLevels        = 1;
    desc.ArraySize        = 1;
    desc.Format           = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage            = D3D11_USAGE_DEFAULT;
    desc.BindFlags        = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA sub{};
    sub.pSysMem          = data;
    sub.SysMemPitch      = (UINT)(w * 4);

    ID3D11Texture2D* tex = nullptr;
    HRESULT hr = d3dDevice_->CreateTexture2D(&desc, &sub, &tex);
    stbi_image_free(data);
    if (FAILED(hr)) return false;

    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc{};
    srvDesc.Format                    = DXGI_FORMAT_R8G8B8A8_UNORM;
    srvDesc.ViewDimension             = D3D11_SRV_DIMENSION_TEXTURE2D;
    srvDesc.Texture2D.MipLevels       = 1;
    hr = d3dDevice_->CreateShaderResourceView(tex, &srvDesc, &bgTexture_);
    tex->Release();
    if (FAILED(hr)) return false;

    bgImgW_ = w; bgImgH_ = h;
    watchedAssetPath_ = path;
    return true;
}

void MainUI::freeBgTexture() {
    if (bgTexture_) { bgTexture_->Release(); bgTexture_ = nullptr; }
    bgImgW_ = bgImgH_ = 0;
}

// ─── Hot Reload Asset Watcher ─────────────────────────────────────────────────
void MainUI::startAssetWatcher(const std::string& path) {
    stopAssetWatcher();
    watchedAssetPath_ = path;
    // Get initial mtime
    HANDLE hf = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hf != INVALID_HANDLE_VALUE) {
        GetFileTime(hf, nullptr, nullptr, &watchedAssetMtime_);
        CloseHandle(hf);
    }
    assetWatchStop_ = false;
    assetWatchThread_ = std::thread([this] {
        while (!assetWatchStop_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (watchedAssetPath_.empty()) continue;
            HANDLE hf2 = CreateFileA(watchedAssetPath_.c_str(), GENERIC_READ,
                FILE_SHARE_READ|FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            if (hf2 == INVALID_HANDLE_VALUE) continue;
            FILETIME ft{};
            GetFileTime(hf2, nullptr, nullptr, &ft);
            CloseHandle(hf2);
            if (CompareFileTime(&ft, &watchedAssetMtime_) != 0) {
                watchedAssetMtime_ = ft;
                assetReloadPending_ = true;
            }
        }
    });
}

void MainUI::stopAssetWatcher() {
    assetWatchStop_ = true;
    if (assetWatchThread_.joinable()) assetWatchThread_.join();
    watchedAssetPath_.clear();
}

// ─── Status Bar ───────────────────────────────────────────────────────────────
void MainUI::renderStatusBar() {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos({vp->WorkPos.x, vp->WorkPos.y + vp->WorkSize.y - 22});
    ImGui::SetNextWindowSize({vp->WorkSize.x, 22});
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {4,2});
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0);
    ImGui::Begin("##statusbar", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoInputs);
    ImGui::Text("%s", statusMsg_.c_str());
    ImGui::SameLine(vp->WorkSize.x - 180);
    if (activeSession_ >= 0)
        ImGui::Text("Results: %zu", sessions_[activeSession_].results.size());
    ImGui::PopStyleVar(2);
    ImGui::End();
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
void MainUI::refreshWatchList() {
    // values are read live during render
}

void MainUI::addToWatchList(const ScanResult& r) {
    WatchEntry e;
    char lbl[64]; snprintf(lbl,sizeof(lbl), pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)r.address);
    e.label   = lbl;
    e.address = r.address;
    e.type    = r.type;
    watchList_.push_back(e);
    statusMsg_ = "Added to watch: " + std::string(lbl);
}

void MainUI::refreshRegionMap() {
    if (pe_.attached()) {
        regionMap_ = pe_.queryRegions(ProtectionFilter::All, RegionTypeFilter::All);
        regionMapDirty_ = false;
    }
}

void MainUI::refreshDisasm(uintptr_t addr) {
    if (!pe_.attached()) return;
    disasmEntries_ = de_.disassemble(addr, 64);
    snprintf(disasmAddrBuf_, sizeof(disasmAddrBuf_),
             pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)addr);
}

void MainUI::refreshMemView(uintptr_t addr, size_t sz) {
    if (!pe_.attached()) return;
    memViewBuf_.resize(sz, 0);
    SIZE_T rd = 0;
    ReadProcessMemory(pe_.handle(), (LPCVOID)addr, memViewBuf_.data(), sz, &rd);
    memViewBuf_.resize(rd);
    memViewBase_ = addr;
    snprintf(memViewAddrBuf_, sizeof(memViewAddrBuf_),
             pe_.is64bit() ? "%016llX" : "%08llX", (unsigned long long)addr);
}

uintptr_t MainUI::parseAddrStr(const char* s) {
    if (!s || !*s) return 0;
    // Module+offset
    const char* plus = strchr(s, '+');
    if (plus) {
        std::string modName(s, plus);
        uintptr_t base = pe_.getModuleBase(modName);
        if (!base) return 0;
        uintptr_t off = (uintptr_t)strtoull(plus+1, 0, 16);
        return base + off;
    }
    return (uintptr_t)strtoull(s, 0, 16);
}

std::string MainUI::formatValue(uintptr_t addr, ValueType t) {
    ScanResult r; r.address = addr; r.type = t;
    size_t tsz = ValueTypeSizes[(int)t];
    if (tsz && pe_.attached()) pe_.readBytes(addr, &r.rawCurrent, tsz);
    return ScanEngine::valueToString(r);
}

ImVec4 MainUI::protectColor(DWORD prot) {
    if (prot & PAGE_EXECUTE_READWRITE)  return {1.0f,0.2f,0.2f,1.f};
    if (prot & PAGE_EXECUTE_READ)       return {1.0f,0.7f,0.0f,1.f};
    if (prot & PAGE_READWRITE)          return {0.3f,0.8f,0.3f,1.f};
    if (prot & PAGE_READONLY)           return {0.5f,0.8f,1.0f,1.f};
    if (prot & PAGE_EXECUTE)            return {1.0f,0.4f,0.8f,1.f};
    return {0.6f,0.6f,0.6f,1.f};
}

void MainUI::applyTheme() {
    if (darkTheme_) {
        ImGui::StyleColorsDark();
        ImGuiStyle& s = ImGui::GetStyle();
        s.WindowRounding    = 4.f;
        s.FrameRounding     = 3.f;
        s.GrabRounding      = 3.f;
        s.Colors[ImGuiCol_WindowBg]         = {0.10f,0.10f,0.13f,1.f};
        s.Colors[ImGuiCol_Header]           = {0.20f,0.22f,0.27f,1.f};
        s.Colors[ImGuiCol_HeaderHovered]    = {0.26f,0.30f,0.40f,1.f};
        s.Colors[ImGuiCol_FrameBg]          = {0.16f,0.18f,0.22f,1.f};
        s.Colors[ImGuiCol_Button]           = {0.20f,0.40f,0.70f,1.f};
        s.Colors[ImGuiCol_ButtonHovered]    = {0.30f,0.50f,0.80f,1.f};
        s.Colors[ImGuiCol_TitleBgActive]    = {0.12f,0.12f,0.20f,1.f};
        s.Colors[ImGuiCol_Tab]              = {0.14f,0.14f,0.20f,1.f};
        s.Colors[ImGuiCol_TabActive]        = {0.20f,0.40f,0.70f,1.f};
        s.Colors[ImGuiCol_TabHovered]       = {0.30f,0.50f,0.80f,1.f};
    } else {
        ImGui::StyleColorsLight();
    }
}

// ─── Async scan launcher ──────────────────────────────────────────────────────
void MainUI::launchScan(std::function<void()> fn) {
    if (scanThread_.joinable()) scanThread_.join();
    scanning_     = true;
    scanProgress_ = 0.f;
    scanDone_     = false;
    scanThread_   = std::thread([this, fn] {
        fn();
        std::lock_guard<std::mutex> lk(scanMtx_);
        scanDone_ = true;
    });
}

void MainUI::pollScanDone() {
    std::lock_guard<std::mutex> lk(scanMtx_);
    if (scanDone_) {
        scanning_  = false;
        scanDone_  = false;
        statusMsg_ = "Scan done. Results: " +
                     (activeSession_ >= 0 ? std::to_string(sessions_[activeSession_].results.size()) : "0") +
                     "  |  " + std::to_string((int)lastStats_.elapsedMs) + " ms  " +
                     std::to_string((int)lastStats_.throughputMBs) + " MB/s";
    }
}

void MainUI::startFirstScan() {
    if (!pe_.attached() || activeSession_ < 0) return;
    ScanOptions opts  = scanOpts_;
    std::string vstr  = scanValue_;
    int si            = activeSession_;
    launchScan([this, opts, vstr, si] {
        auto cb = [this](float p){ scanProgress_ = p; };
        if (opts.type == ValueType::AoB)
            lastStats_ = se_.aobScan(sessions_[si], aobPatternBuf_, opts.protFilter, opts.regionFilter, cb);
        else if (opts.type == ValueType::String || opts.type == ValueType::WString)
            lastStats_ = se_.stringScan(sessions_[si], strPatBuf_, opts.strCaseSensitive, opts.type==ValueType::WString, opts.protFilter, opts.regionFilter, cb);
        else
            lastStats_ = se_.firstScan(sessions_[si], opts, vstr, cb);
    });
}

void MainUI::startNextScan() {
    if (!pe_.attached() || activeSession_ < 0) return;
    ScanOptions opts = scanOpts_;
    std::string vstr = scanValue_;
    int si           = activeSession_;
    launchScan([this, opts, vstr, si] {
        lastStats_ = se_.nextScan(sessions_[si], opts, vstr, [this](float p){ scanProgress_ = p; });
    });
}

void MainUI::startAoBScan() {
    scanOpts_.type = ValueType::AoB;
    startFirstScan();
}

void MainUI::startStringScan() {
    scanOpts_.type = ValueType::String;
    startFirstScan();
}


// ─── XRef Scanner Window ──────────────────────────────────────────────────────
void MainUI::renderXRef() {
    ImGui::SetNextWindowSize({800, 450}, ImGuiCond_FirstUseEver);
    ImGui::Begin("XRef Scanner", &showXRef_);

    ImGui::Text("Target Address:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220);
    ImGui::InputText("##xreftgt", xrefTargetBuf_, sizeof(xrefTargetBuf_));
    ImGui::SameLine();

    if (!xrefScanning_) {
        ImGui::PushStyleColor(ImGuiCol_Button, {0.6f, 0.2f, 0.8f, 1.f});
        if (ImGui::Button("Scan All Regions") && pe_.attached()) {
            uintptr_t tgt = parseAddrStr(xrefTargetBuf_);
            if (tgt) {
                xrefScanning_ = true;
                xrefProgress_ = 0.f;
                xrefResults_.clear();
                if (xrefThread_.joinable()) xrefThread_.join();
                xrefThread_ = std::thread([this, tgt] {
                    xrefResults_ = de_.findXRefsGlobal(tgt,
                        [this](float p){ xrefProgress_ = p; });
                    xrefScanning_ = false;
                });
            }
        }
        ImGui::PopStyleColor();
        ImGui::SameLine();
        if (ImGui::Button("Scan Module") && pe_.attached() && selectedModule_ >= 0) {
            uintptr_t tgt = parseAddrStr(xrefTargetBuf_);
            auto& mod = pe_.procInfo().modules[selectedModule_];
            if (tgt && mod.base) {
                xrefResults_ = de_.findXRefs(tgt, mod.base, mod.size);
                statusMsg_ = "XRef scan in " + mod.name + ": " +
                             std::to_string(xrefResults_.size()) + " refs";
            }
        }
    } else {
        ImGui::ProgressBar(xrefProgress_, {220, 0});
        ImGui::SameLine();
        ImGui::TextColored({1,1,0,1}, "Scanning...");
    }

    ImGui::Text("%zu cross-references found", xrefResults_.size());
    ImGui::Separator();

    ImGui::Columns(4, "xrefcols", true);
    ImGui::SetColumnWidth(0, 160); ImGui::Text("From Address");  ImGui::NextColumn();
    ImGui::SetColumnWidth(1, 70);  ImGui::Text("Type");          ImGui::NextColumn();
    ImGui::SetColumnWidth(2, 200); ImGui::Text("Symbol");        ImGui::NextColumn();
    ImGui::Text("Instruction");                                   ImGui::NextColumn();
    ImGui::Separator();

    ImGuiListClipper clipper;
    clipper.Begin((int)xrefResults_.size());
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            auto& x = xrefResults_[i];
            ImGui::PushID(i);

            char addrStr[32];
            snprintf(addrStr, sizeof(addrStr),
                     pe_.is64bit() ? "%016llX" : "%08llX",
                     (unsigned long long)x.from);

            ImVec4 typeColor = {1,1,1,1};
            if      (x.type == "CALL") typeColor = {1.0f, 0.8f, 0.0f, 1.f};
            else if (x.type == "JMP")  typeColor = {0.4f, 0.8f, 1.0f, 1.f};
            else if (x.type == "Jcc")  typeColor = {0.5f, 1.0f, 0.7f, 1.f};

            if (ImGui::Selectable(addrStr, false,
                    ImGuiSelectableFlags_SpanAllColumns |
                    ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(0)) {
                    refreshDisasm(x.from);
                    disasmBase_ = x.from;
                    showDisasm_  = true;
                }
            }
            if (ImGui::BeginPopupContextItem("##xrefctx")) {
                if (ImGui::MenuItem("Disassemble here"))
                    { refreshDisasm(x.from); disasmBase_ = x.from; showDisasm_ = true; }
                if (ImGui::MenuItem("View in Memory"))
                    { refreshMemView(x.from, 256); showMemView_ = true; }
                if (ImGui::MenuItem("Add to Watch List")) {
                    WatchEntry w;
                    w.label   = "XRef@" + std::string(addrStr);
                    w.address = x.from;
                    w.type    = ValueType::UInt64;
                    watchList_.push_back(w);
                }
                if (ImGui::MenuItem("Copy Address"))
                    ImGui::SetClipboardText(addrStr);
                ImGui::EndPopup();
            }
            ImGui::NextColumn();

            ImGui::TextColored(typeColor, "%s", x.type.c_str());
            ImGui::NextColumn();

            std::string sym = de_.resolveSymbol(x.from);
            ImGui::TextDisabled("%s", sym.empty() ? "-" : sym.c_str());
            ImGui::NextColumn();

            ImGui::Text("%s", x.context.c_str());
            ImGui::NextColumn();

            ImGui::PopID();
        }
    }
    clipper.End();
    ImGui::Columns(1);
    ImGui::End();
}
