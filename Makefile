# MemScanner – MinGW64 / GCC Makefile
# Dependencies: Dear ImGui v1.91.6 + Zydis v4 amalgamated

CXX   := x86_64-w64-mingw32-g++
CC    := x86_64-w64-mingw32-gcc
STRIP := x86_64-w64-mingw32-strip

TARGET := MemScanner.exe
BUILD  := build

CXXFLAGS := \
    -std=c++17 -O2 -Wall -Wextra \
    -Wno-unused-parameter \
    -Wno-cast-function-type \
    -Wno-missing-field-initializers \
    -mwindows \
    -Isrc -Isrc/imgui -Isrc/zydis \
    -DWIN32_LEAN_AND_MEAN -DNOMINMAX \
    -D_WIN32_WINNT=0x0601 \
    -DZYDIS_STATIC_BUILD \
    -DZYCORE_STATIC_BUILD

CFLAGS_ZYDIS := \
    -std=c11 -O2 \
    -Isrc/zydis \
    -DZYDIS_STATIC_BUILD \
    -DZYCORE_STATIC_BUILD \
    -Wno-unused-function \
    -Wno-missing-field-initializers \
    -Wno-implicit-fallthrough

LDFLAGS := \
    -mwindows \
    -static-libgcc -static-libstdc++ \
    -Wl,-subsystem,windows \
    -ld3d11 -ldxgi -ld3dcompiler \
    -lpsapi -ldbghelp \
    -lkernel32 -luser32 -lgdi32 -lshell32 \
    -lole32 -lcomctl32 -lshlwapi \
    -limm32 -ldwmapi

# ── C++ sources ───────────────────────────────────────────────────────────────
SRCS_CXX := \
    src/main.cpp \
    src/ProcessEngine.cpp \
    src/ScanEngine.cpp \
    src/DisasmEngine.cpp \
    src/MainUI.cpp \
    src/imgui/imgui.cpp \
    src/imgui/imgui_draw.cpp \
    src/imgui/imgui_tables.cpp \
    src/imgui/imgui_widgets.cpp \
    src/imgui/imgui_impl_win32.cpp \
    src/imgui/imgui_impl_dx11.cpp

# ── Zydis amalgamated (single .c file) ───────────────────────────────────────
SRCS_C := src/zydis/Zydis.c

OBJS_CXX := $(patsubst %.cpp, $(BUILD)/%.o, $(SRCS_CXX))
OBJS_C   := $(patsubst %.c,   $(BUILD)/%.o, $(SRCS_C))
OBJS     := $(OBJS_CXX) $(OBJS_C)

# ── Rules ─────────────────────────────────────────────────────────────────────
.PHONY: all clean release deps

all: $(BUILD)/$(TARGET)

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_ZYDIS) -c $< -o $@

$(BUILD)/$(TARGET): $(OBJS)
	$(CXX) $^ -o $@ $(LDFLAGS)
	@echo "Build complete: $@"

release: $(BUILD)/$(TARGET)
	$(STRIP) --strip-all $(BUILD)/$(TARGET)
	@echo "Stripped: $(BUILD)/$(TARGET)"

clean:
	rm -rf $(BUILD)

# ── Dependency fetch (run once) ───────────────────────────────────────────────
# Fetches Dear ImGui via git. Zydis must be downloaded MANUALLY (see below).
deps:
	@echo ">>> Fetching Dear ImGui v1.91.6..."
	git clone --depth 1 -b v1.91.6 https://github.com/ocornut/imgui _imgui_tmp
	mkdir -p src/imgui
	cp _imgui_tmp/imgui.cpp _imgui_tmp/imgui.h \
	   _imgui_tmp/imgui_draw.cpp _imgui_tmp/imgui_tables.cpp \
	   _imgui_tmp/imgui_widgets.cpp _imgui_tmp/imgui_internal.h \
	   _imgui_tmp/imconfig.h src/imgui/
	cp _imgui_tmp/imstb_*.h src/imgui/
	cp _imgui_tmp/backends/imgui_impl_win32.cpp \
	   _imgui_tmp/backends/imgui_impl_win32.h \
	   _imgui_tmp/backends/imgui_impl_dx11.cpp \
	   _imgui_tmp/backends/imgui_impl_dx11.h src/imgui/
	rm -rf _imgui_tmp
	@echo ""
	@echo ">>> ImGui done."
	@echo ">>> Zydis: download amalgamated zip manually:"
	@echo "    https://github.com/zyantific/zydis/releases/latest"
	@echo "    → zydis-amalgamated.zip"
	@echo "    Extract, copy Zydis.h + Zydis.c in src/zydis/"
	@echo "    Then run: make"