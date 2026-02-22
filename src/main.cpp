#include "MainUI.h"
#include <d3d11.h>
#include <dxgi.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "psapi.lib")

// ─── DX11 state ──────────────────────────────────────────────────────────────
static ID3D11Device*            g_pd3dDevice           = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext    = nullptr;
static IDXGISwapChain*          g_pSwapChain           = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;
static HWND                     g_hwnd                 = nullptr;

static void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

static void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount                        = 2;
    sd.BufferDesc.Width                   = 0;
    sd.BufferDesc.Height                  = 0;
    sd.BufferDesc.Format                  = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator   = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags                              = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage                        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow                       = hWnd;
    sd.SampleDesc.Count                   = 1;
    sd.SampleDesc.Quality                 = 0;
    sd.Windowed                           = TRUE;
    sd.SwapEffect                         = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION,
        &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res == DXGI_ERROR_UNSUPPORTED)
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
            createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION,
            &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (res != S_OK) return false;
    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain)         { g_pSwapChain->Release();         g_pSwapChain         = nullptr; }
    if (g_pd3dDeviceContext)  { g_pd3dDeviceContext->Release();  g_pd3dDeviceContext  = nullptr; }
    if (g_pd3dDevice)         { g_pd3dDevice->Release();         g_pd3dDevice         = nullptr; }
}

// ─── Win32 message handler ───────────────────────────────────────────────────
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND h, UINT m, WPARAM w, LPARAM l);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
        case WM_SIZE:
            if (wParam != SIZE_MINIMIZED && g_pd3dDevice) {
                CleanupRenderTarget();
                g_pSwapChain->ResizeBuffers(0, LOWORD(lParam), HIWORD(lParam),
                                            DXGI_FORMAT_UNKNOWN, 0);
                CreateRenderTarget();
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xFFF0) == SC_KEYMENU) return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ─── WinMain ──────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    // Elevate process token for PROCESS_VM_READ on protected processes
    HANDLE hToken; HANDLE hProcess = GetCurrentProcess();
    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp{};
        LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid);
        tp.PrivilegeCount             = 1;
        tp.Privileges[0].Attributes  = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
        CloseHandle(hToken);
    }

    WNDCLASSEXW wc{ sizeof(wc), CS_CLASSDC, WndProc, 0, 0, hInstance,
                    LoadIcon(nullptr,IDI_APPLICATION), LoadCursor(nullptr,IDC_ARROW),
                    nullptr, nullptr, L"MemScannerWnd", nullptr };
    RegisterClassExW(&wc);
    g_hwnd = CreateWindowExW(0, wc.lpszClassName, L"MemScanner  — Memory Analysis",
                              WS_OVERLAPPEDWINDOW, 100, 100, 1600, 1000,
                              nullptr, nullptr, hInstance, nullptr);
    if (!g_hwnd) { UnregisterClassW(wc.lpszClassName, hInstance); return 1; }

    if (!CreateDeviceD3D(g_hwnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(wc.lpszClassName, hInstance);
        return 1;
    }

    ShowWindow(g_hwnd, SW_SHOWMAXIMIZED);
    UpdateWindow(g_hwnd);

    MainUI ui;
    if (!ui.init(g_hwnd, g_pd3dDevice, g_pd3dDeviceContext)) return 1;

    MSG msg{};
    while (!ui.shouldQuit()) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) goto cleanup;
        }

        // Clear — color driven by MainUI background setting
        float clearColor[4];
        ui.getClearColor(clearColor);
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clearColor);

        ui.render();

        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(1, 0); // vsync
    }

cleanup:
    ui.shutdown();
    CleanupDeviceD3D();
    DestroyWindow(g_hwnd);
    UnregisterClassW(wc.lpszClassName, hInstance);
    return 0;
}
