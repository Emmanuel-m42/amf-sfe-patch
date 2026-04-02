/*
 * AMF Split Frame Encode (SFE) Runtime Memory Patcher
 *
 * Launches a target application, waits for amfrtdrv64.dll to load,
 * then patches the HEVC SFE heuristic check in memory.
 *
 * Build (MSVC):  cl /O2 /W4 amf-sfe-launch.c /Fe:amf-sfe-launch.exe advapi32.lib
 * Build (MinGW): x86_64-w64-mingw32-gcc -O2 -Wall -o amf-sfe-launch.exe amf-sfe-launch.c -lpsapi
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

/* ── Privilege escalation ────────────────────────────────────────────── */

static int enable_debug_privilege(void) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return 0;

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return 0;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    return ok && err == ERROR_SUCCESS;
}

/* ── Pattern definitions ─────────────────────────────────────────────── */

typedef struct {
    const char *name;
    const uint8_t *pattern;
    size_t pattern_len;
    size_t patch_offset;
    const uint8_t *patch;
    size_t patch_len;
} PatchDef;

static const uint8_t hevc_pattern_v1[] = {
    0x80, 0xBE, 0x16, 0x08, 0x00, 0x00, 0x00, 0x74, 0x2F  /* CMP [RSI+0x816],0 / JZ +0x2F */
};
static const uint8_t hevc_pattern_v2[] = {
    0x80, 0xBB, 0xFE, 0x0D, 0x00, 0x00, 0x00, 0x74, 0x2E  /* CMP [RBX+0xDFE],0 / JZ +0x2E */
};
static const uint8_t nop2[] = { 0x90, 0x90 };

static const uint8_t sfe_wl_v1_pattern[] = {
    0x45, 0x84, 0xE4, 0x74, 0x05, 0x44, 0x88, 0x3E, 0xEB, 0x21
};
static const uint8_t sfe_wl_v1_patch[] = {
    0xC6, 0x06, 0x01, 0x90, 0x90, 0x90, 0x90, 0x90, 0xEB, 0x21
};
static const uint8_t sfe_wl_v2_pattern[] = {
    0x45, 0x84, 0xF6, 0x74, 0x05, 0x40, 0x88, 0x2E, 0xEB, 0x29
};
static const uint8_t sfe_wl_v2_patch[] = {
    0xC6, 0x06, 0x01, 0x90, 0x90, 0x90, 0x90, 0x90, 0xEB, 0x29
};

static const uint8_t vcn_count_pattern[] = {
    0xFF, 0x50, 0x20, 0x48, 0x83, 0xF8, 0x02, 0x0F, 0x82
};
static const uint8_t nop6[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

static const PatchDef patches[] = {
    {
        .name         = "HEVC SFE heuristic bypass (v1: RSI+0x816)",
        .pattern      = hevc_pattern_v1,
        .pattern_len  = sizeof(hevc_pattern_v1),
        .patch_offset = 7,
        .patch        = nop2,
        .patch_len    = sizeof(nop2),
    },
    {
        .name         = "HEVC SFE heuristic bypass (v2: RBX+0xDFE)",
        .pattern      = hevc_pattern_v2,
        .pattern_len  = sizeof(hevc_pattern_v2),
        .patch_offset = 7,
        .patch        = nop2,
        .patch_len    = sizeof(nop2),
    },
    {
        .name         = "SFE whitelist bypass (v1: TEST R12B)",
        .pattern      = sfe_wl_v1_pattern,
        .pattern_len  = sizeof(sfe_wl_v1_pattern),
        .patch_offset = 0,
        .patch        = sfe_wl_v1_patch,
        .patch_len    = sizeof(sfe_wl_v1_patch),
    },
    {
        .name         = "SFE whitelist bypass (v2: TEST R14B)",
        .pattern      = sfe_wl_v2_pattern,
        .pattern_len  = sizeof(sfe_wl_v2_pattern),
        .patch_offset = 0,
        .patch        = sfe_wl_v2_patch,
        .patch_len    = sizeof(sfe_wl_v2_patch),
    },
    {
        .name         = "VCN instance count bypass (force >= 2)",
        .pattern      = vcn_count_pattern,
        .pattern_len  = sizeof(vcn_count_pattern),
        .patch_offset = 7,
        .patch        = nop6,
        .patch_len    = sizeof(nop6),
    },
};
static const size_t num_patches = sizeof(patches) / sizeof(patches[0]);

/* ── Helpers ─────────────────────────────────────────────────────────── */

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02X ", data[i]);
}

/*
 * Find a loaded module by name in the target process.
 * Returns the base address and size via out params.
 */
static int find_module(HANDLE hProcess, const char *module_name,
                       uint8_t **base_out, size_t *size_out) {
    HMODULE modules[1024];
    DWORD needed;

    if (!EnumProcessModulesEx(hProcess, modules, sizeof(modules), &needed, LIST_MODULES_ALL))
        return 0;

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        char name[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, modules[i], name, sizeof(name))) {
            if (_stricmp(name, module_name) == 0) {
                MODULEINFO mi;
                if (GetModuleInformation(hProcess, modules[i], &mi, sizeof(mi))) {
                    *base_out = (uint8_t *)mi.lpBaseOfDll;
                    *size_out = mi.SizeOfImage;
                    return 1;
                }
            }
        }
    }
    return 0;
}

/*
 * Pattern scan remote process memory.
 * Returns number of matches; sets match_offset to offset from base of first match.
 */
static int remote_pattern_scan(HANDLE hProcess, uint8_t *base, size_t region_size,
                               const uint8_t *pattern, size_t pattern_len,
                               size_t *match_offset) {
    /* Read the entire module into local memory for fast scanning */
    uint8_t *local = (uint8_t *)malloc(region_size);
    if (!local) return -1;

    SIZE_T bytes_read;
    if (!ReadProcessMemory(hProcess, base, local, region_size, &bytes_read)) {
        /* Try reading in pages — some regions may be unreadable */
        memset(local, 0, region_size);
        size_t page_size = 4096;
        for (size_t off = 0; off < region_size; off += page_size) {
            size_t chunk = region_size - off;
            if (chunk > page_size) chunk = page_size;
            ReadProcessMemory(hProcess, base + off, local + off, chunk, &bytes_read);
        }
    }

    int count = 0;
    for (size_t i = 0; i <= region_size - pattern_len; i++) {
        if (memcmp(local + i, pattern, pattern_len) == 0) {
            if (count == 0 && match_offset)
                *match_offset = i;
            count++;
        }
    }

    free(local);
    return count;
}

/*
 * Apply a patch at a specific address in the remote process.
 */
static int remote_patch(HANDLE hProcess, uint8_t *addr,
                        const uint8_t *patch_bytes, size_t patch_len) {
    DWORD old_protect;
    if (!VirtualProtectEx(hProcess, addr, patch_len, PAGE_EXECUTE_READWRITE, &old_protect)) {
        fprintf(stderr, "  VirtualProtectEx failed: %lu\n", GetLastError());
        return -1;
    }

    SIZE_T written;
    if (!WriteProcessMemory(hProcess, addr, patch_bytes, patch_len, &written) || written != patch_len) {
        fprintf(stderr, "  WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualProtectEx(hProcess, addr, patch_len, old_protect, &old_protect);
        return -1;
    }

    /* Restore original protection */
    VirtualProtectEx(hProcess, addr, patch_len, old_protect, &old_protect);

    /* Flush instruction cache */
    FlushInstructionCache(hProcess, addr, patch_len);

    return 0;
}

/* ── Usage ───────────────────────────────────────────────────────────── */

static void usage(const char *argv0) {
    printf("AMF Split Frame Encode (SFE) Runtime Patcher\n");
    printf("Launches a process and patches amfrtdrv64.dll in memory.\n\n");
    printf("Usage:\n");
    printf("  %s <executable> [--args \"arg1 arg2 ...\"]\n", argv0);
    printf("  %s --pid <pid>     Attach to existing process\n", argv0);
    printf("  %s --wait <name>   Wait for process by name, then patch\n", argv0);
    printf("\nExamples:\n");
    printf("  %s \"C:\\Program Files\\Sunshine\\sunshine.exe\"\n", argv0);
    printf("  %s --pid 12345\n", argv0);
    printf("  %s --wait sunshine.exe\n", argv0);
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (enable_debug_privilege())
        printf("SeDebugPrivilege enabled.\n");
    else
        printf("Warning: Could not enable SeDebugPrivilege (run as admin).\n");

    const char *exe_path = NULL;
    const char *extra_args = NULL;
    DWORD target_pid = 0;
    const char *wait_name = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--args") == 0 && i + 1 < argc) {
            extra_args = argv[++i];
        } else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
            target_pid = (DWORD)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--wait") == 0 && i + 1 < argc) {
            wait_name = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            exe_path = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (!exe_path && !target_pid && !wait_name) {
        usage(argv[0]);
        return 1;
    }

    HANDLE hProcess = NULL;
    DWORD pid = 0;

    if (wait_name) {
        /* ── Wait for process by name ── */
        printf("Waiting for %s to start...\n", wait_name);
        while (1) {
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE) { Sleep(500); continue; }

            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(pe);
            if (Process32First(snap, &pe)) {
                do {
                    if (_stricmp(pe.szExeFile, wait_name) == 0) {
                        pid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);
            if (pid) break;
            Sleep(500);
        }
        printf("Found %s (PID %lu)\n", wait_name, pid);
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            fprintf(stderr, "Failed to open process: %lu\n", GetLastError());
            return 1;
        }

    } else if (target_pid) {
        /* ── Attach to existing PID ── */
        pid = target_pid;
        printf("Attaching to PID %lu\n", pid);
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            fprintf(stderr, "Failed to open process: %lu\n", GetLastError());
            return 1;
        }

    } else {
        /* ── Launch new process suspended ── */
        printf("Launching: %s\n", exe_path);

        /* Build command line */
        char cmdline[32768];
        if (extra_args)
            snprintf(cmdline, sizeof(cmdline), "\"%s\" %s", exe_path, extra_args);
        else
            snprintf(cmdline, sizeof(cmdline), "\"%s\"", exe_path);

        /* Derive working directory from exe path */
        char work_dir[MAX_PATH] = {0};
        strncpy(work_dir, exe_path, MAX_PATH - 1);
        char *last_slash = strrchr(work_dir, '\\');
        if (!last_slash) last_slash = strrchr(work_dir, '/');
        if (last_slash) *last_slash = '\0';
        else work_dir[0] = '\0';

        STARTUPINFOA si = { .cb = sizeof(si) };
        PROCESS_INFORMATION pi = {0};

        if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                            CREATE_SUSPENDED, NULL,
                            work_dir[0] ? work_dir : NULL, &si, &pi)) {
            fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
            return 1;
        }

        pid = pi.dwProcessId;
        hProcess = pi.hProcess;
        printf("Process created (PID %lu), suspended.\n", pid);

        /* Resume and wait for DLL to load */
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
    }

    /* ── Wait for amfrtdrv64.dll to be loaded ── */
    printf("Waiting for amfrtdrv64.dll to be loaded...\n");

    uint8_t *dll_base = NULL;
    size_t dll_size = 0;
    int waited = 0;

    while (1) {
        if (find_module(hProcess, "amfrtdrv64.dll", &dll_base, &dll_size))
            break;

        /* Check if process is still alive */
        DWORD exit_code;
        if (GetExitCodeProcess(hProcess, &exit_code) && exit_code != STILL_ACTIVE) {
            fprintf(stderr, "Process exited before amfrtdrv64.dll was loaded.\n");
            CloseHandle(hProcess);
            return 1;
        }

        Sleep(250);
        waited++;
        if (waited % 120 == 0)
            printf("  Still waiting... (%d seconds)\n", waited / 4);
    }

    printf("Found amfrtdrv64.dll at 0x%p (%zu bytes)\n\n", dll_base, dll_size);

    /* Give the DLL a moment to finish initialization */
    Sleep(500);

    /* ── Apply patches ── */
    int any_error = 0;
    int total_patched = 0;
    int any_hevc_matched = 0;

    for (size_t p = 0; p < num_patches; p++) {
        const PatchDef *pd = &patches[p];
        printf("[%s]\n", pd->name);
        printf("  Pattern: ");
        print_hex(pd->pattern, pd->pattern_len);
        printf("\n");

        size_t match_offset = 0;
        int matches = remote_pattern_scan(hProcess, dll_base, dll_size,
                                          pd->pattern, pd->pattern_len, &match_offset);

        if (matches == 0) {
            /* Check if already patched */
            uint8_t *patched_pattern = (uint8_t *)malloc(pd->pattern_len);
            memcpy(patched_pattern, pd->pattern, pd->pattern_len);
            memcpy(patched_pattern + pd->patch_offset, pd->patch, pd->patch_len);

            int pm = remote_pattern_scan(hProcess, dll_base, dll_size,
                                         patched_pattern, pd->pattern_len, &match_offset);
            free(patched_pattern);

            if (pm == 1) {
                printf("  Status:  ALREADY PATCHED at base+0x%zX\n\n", match_offset);
                any_hevc_matched = 1;
                continue;
            }

            printf("  Status:  Not found (different driver version)\n\n");
            continue;
        }

        if (matches > 1) {
            fprintf(stderr, "  ERROR:   Pattern found %d times (expected 1). Skipping.\n\n", matches);
            any_error = 1;
            continue;
        }

        uint8_t *patch_addr = dll_base + match_offset + pd->patch_offset;
        printf("  Found:   1 match at base+0x%zX\n", match_offset);
        printf("  Patch:   0x%p: ", patch_addr);
        print_hex(pd->patch, pd->patch_len);
        printf("\n");

        any_hevc_matched = 1;

        if (remote_patch(hProcess, patch_addr, pd->patch, pd->patch_len) == 0) {
            total_patched++;
            printf("  Applied: SUCCESS\n");
        } else {
            fprintf(stderr, "  Applied: FAILED\n");
            any_error = 1;
        }
        printf("\n");
    }

    CloseHandle(hProcess);

    if (any_error) {
        fprintf(stderr, "Some patches failed. Check output above.\n");
        return 1;
    }

    if (!any_hevc_matched) {
        fprintf(stderr, "Error: No known HEVC SFE pattern matched this DLL version.\n");
        return 1;
    }

    if (total_patched > 0) {
        printf("All %d patch(es) applied successfully to PID %lu.\n", total_patched, pid);
        printf("Split frame encoding should now be active for HEVC at any resolution.\n");
    } else {
        printf("No patches needed (already patched?).\n");
    }

    return 0;
}
