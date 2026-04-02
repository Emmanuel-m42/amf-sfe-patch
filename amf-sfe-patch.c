/*
 * AMF Split Frame Encode (SFE) File Patcher
 *
 * Patches amfrtdrv64.dll to force-enable split frame encoding (dual VCN)
 * at any resolution by NOPing out the heuristic check that disables it.
 *
 * Pattern: 80 BE 16 08 00 00 00 74 2F  (CMP [RSI+0x816],0 / JZ +0x2F)
 * Patch:   last 2 bytes -> 90 90        (NOP NOP — always fall through)
 *
 * Build (MSVC):  cl /O2 /W4 amf-sfe-patch.c /Fe:amf-sfe-patch.exe
 * Build (MinGW): gcc -O2 -Wall -o amf-sfe-patch.exe amf-sfe-patch.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
#else
#include <sys/stat.h>
#endif

/* ── Pattern definitions (extensible for AV1 later) ─────────────────── */

typedef struct {
    const char *name;
    const uint8_t *pattern;
    size_t pattern_len;
    size_t patch_offset;    /* offset within pattern to start patching */
    const uint8_t *patch;
    size_t patch_len;
} PatchDef;

/* Driver version variants — same heuristic check, different register/offset/jump */
static const uint8_t hevc_pattern_v1[] = {
    0x80, 0xBE, 0x16, 0x08, 0x00, 0x00, 0x00, 0x74, 0x2F  /* CMP [RSI+0x816],0 / JZ +0x2F */
};
static const uint8_t hevc_pattern_v2[] = {
    0x80, 0xBB, 0xFE, 0x0D, 0x00, 0x00, 0x00, 0x74, 0x2E  /* CMP [RBX+0xDFE],0 / JZ +0x2E */
};
static const uint8_t nop2[] = { 0x90, 0x90 };

/* Secondary patch: inside dual VCN setup function, bypass device ID whitelist.
   Original: TEST R14B,R14B / JZ +5 / MOV [RSI],CH / JMP +0x29
   Patched:  MOV byte [RSI],1 / 5x NOP / JMP +0x29
   Forces SFE enable flag to 1 unconditionally, skipping resolution/device checks. */
/* Whitelist bypass v1: TEST R12B / JZ / MOV [RSI],R15B / JMP +0x21 (u0420529 driver) */
static const uint8_t sfe_wl_v1_pattern[] = {
    0x45, 0x84, 0xE4, 0x74, 0x05, 0x44, 0x88, 0x3E, 0xEB, 0x21
};
static const uint8_t sfe_wl_v1_patch[] = {
    0xC6, 0x06, 0x01, 0x90, 0x90, 0x90, 0x90, 0x90, 0xEB, 0x21
};

/* Whitelist bypass v2: TEST R14B / JZ / MOV [RSI],CH / JMP +0x29 (u0198975 driver) */
static const uint8_t sfe_wl_v2_pattern[] = {
    0x45, 0x84, 0xF6, 0x74, 0x05, 0x40, 0x88, 0x2E, 0xEB, 0x29
};
static const uint8_t sfe_wl_v2_patch[] = {
    0xC6, 0x06, 0x01, 0x90, 0x90, 0x90, 0x90, 0x90, 0xEB, 0x29
};

/* VCN instance count bypass: CALL [RAX+0x20] / CMP RAX,2 / JB exit
   NOPs the JB so it always continues even if driver reports < 2 instances */
static const uint8_t vcn_count_pattern[] = {
    0xFF, 0x50, 0x20, 0x48, 0x83, 0xF8, 0x02, 0x0F, 0x82
};
static const uint8_t nop6[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

/* Add AV1 pattern here when found */

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
        .patch_offset = 7,  /* NOP the JB instruction (6 bytes) */
        .patch        = nop6,
        .patch_len    = sizeof(nop6),
    },
    /* Future: AV1 entry */
};
static const size_t num_patches = sizeof(patches) / sizeof(patches[0]);

/* ── Helpers ─────────────────────────────────────────────────────────── */

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02X ", data[i]);
}

static uint8_t *read_file(const char *path, size_t *out_size) {
#ifdef _WIN32
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        fprintf(stderr, "%s: cannot open for reading (GetLastError=%lu", path, err);
        if (err == 2)  fprintf(stderr, " FILE_NOT_FOUND");
        if (err == 3)  fprintf(stderr, " PATH_NOT_FOUND");
        if (err == 5)  fprintf(stderr, " ACCESS_DENIED");
        if (err == 32) fprintf(stderr, " SHARING_VIOLATION — is AMD software or Apollo still running?");
        fprintf(stderr, ")\n");
        return NULL;
    }
    LARGE_INTEGER li;
    if (!GetFileSizeEx(hFile, &li) || li.QuadPart <= 0) {
        fprintf(stderr, "%s: cannot get file size (GetLastError=%lu)\n", path, GetLastError());
        CloseHandle(hFile);
        return NULL;
    }
    size_t sz = (size_t)li.QuadPart;
    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) {
        fprintf(stderr, "%s: malloc failed (%zu bytes)\n", path, sz);
        CloseHandle(hFile);
        return NULL;
    }
    DWORD bytesRead;
    if (!ReadFile(hFile, buf, (DWORD)sz, &bytesRead, NULL) || bytesRead != (DWORD)sz) {
        fprintf(stderr, "%s: ReadFile failed (GetLastError=%lu, read %lu/%zu)\n",
                path, GetLastError(), (unsigned long)bytesRead, sz);
        free(buf);
        CloseHandle(hFile);
        return NULL;
    }
    CloseHandle(hFile);
    *out_size = sz;
    return buf;
#else
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }

    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *out_size = (size_t)sz;
    return buf;
#endif
}

static int write_file(const char *path, const uint8_t *data, size_t size) {
#ifdef _WIN32
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "%s: CreateFile failed (GetLastError=%lu)\n", path, GetLastError());
        return -1;
    }
    DWORD written;
    if (!WriteFile(hFile, data, (DWORD)size, &written, NULL) || written != (DWORD)size) {
        fprintf(stderr, "%s: WriteFile failed (GetLastError=%lu, wrote %lu/%zu)\n",
                path, GetLastError(), (unsigned long)written, size);
        CloseHandle(hFile);
        return -1;
    }
    CloseHandle(hFile);
    return 0;
#else
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    if (fwrite(data, 1, size, f) != size) {
        perror("fwrite");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
#endif
}

static int copy_file(const char *src, const char *dst) {
#ifdef _WIN32
    if (!CopyFileA(src, dst, FALSE)) {
        fprintf(stderr, "Failed to copy %s -> %s (error %lu)\n", src, dst, GetLastError());
        return -1;
    }
    return 0;
#else
    size_t sz;
    uint8_t *data = read_file(src, &sz);
    if (!data) return -1;
    int r = write_file(dst, data, sz);
    free(data);
    return r;
#endif
}

/* Returns number of matches found. Sets *match_offset to offset of FIRST match. */
static int pattern_scan(const uint8_t *data, size_t data_len,
                        const uint8_t *pattern, size_t pattern_len,
                        size_t *match_offset) {
    int count = 0;
    if (data_len < pattern_len) return 0;

    for (size_t i = 0; i <= data_len - pattern_len; i++) {
        if (memcmp(data + i, pattern, pattern_len) == 0) {
            if (count == 0 && match_offset)
                *match_offset = i;
            count++;
        }
    }
    return count;
}

/* ── Debug helpers ────────────────────────────────────────────────────── */

#ifdef _WIN32
static int is_elevated(void) {
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size))
            elevated = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated;
}

static void debug_file_info(const char *label, const char *path) {
    DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD err = GetLastError();
        printf("  [debug] %s: does not exist or inaccessible (GetLastError=%lu)\n", label, err);
        return;
    }

    printf("  [debug] %s: exists, attrs=0x%lX", label, (unsigned long)attrs);
    if (attrs & FILE_ATTRIBUTE_READONLY)  printf(" READONLY");
    if (attrs & FILE_ATTRIBUTE_SYSTEM)    printf(" SYSTEM");
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) printf(" DIR");
    printf("\n");

    /* Try opening for write to test actual access */
    HANDLE hFile = CreateFileA(path,
        (attrs & FILE_ATTRIBUTE_DIRECTORY) ? FILE_LIST_DIRECTORY : GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        (attrs & FILE_ATTRIBUTE_DIRECTORY) ? FILE_FLAG_BACKUP_SEMANTICS : 0,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("  [debug] %s: write access DENIED (GetLastError=%lu", label, err);
        if (err == 5)    printf(" ACCESS_DENIED");
        if (err == 32)   printf(" SHARING_VIOLATION");
        if (err == 1314) printf(" PRIVILEGE_NOT_HELD");
        printf(")\n");
    } else {
        printf("  [debug] %s: write access OK\n", label);
        CloseHandle(hFile);
    }
}
#endif

/* ── Take ownership of a file (for DriverStore/TrustedInstaller) ────── */

#ifdef _WIN32
static int take_ownership(const char *path) {
    char cmd[4096];
    int rc;

    printf("  [debug] takeown target: %s\n", path);

    /* takeown /f "<path>" /a — gives Administrators ownership */
    snprintf(cmd, sizeof(cmd), "takeown /f \"%s\" /a >nul 2>&1", path);
    rc = system(cmd);
    if (rc != 0) {
        printf("  [debug] takeown exit code: %d\n", rc);
        fprintf(stderr, "Warning: takeown failed for %s\n", path);
    } else {
        printf("  [debug] takeown succeeded\n");
    }

    /* icacls "<path>" /grant Administrators:F — full control */
    snprintf(cmd, sizeof(cmd), "icacls \"%s\" /grant Administrators:F >nul 2>&1", path);
    rc = system(cmd);
    if (rc != 0) {
        printf("  [debug] icacls exit code: %d\n", rc);
        fprintf(stderr, "Warning: icacls failed for %s\n", path);
    } else {
        printf("  [debug] icacls succeeded\n");
    }

    return 0;
}

/* Take ownership of a file and its parent directory */
static int take_ownership_for_write(const char *file_path) {
    printf("\n  [debug] --- Ownership debug info ---\n");
    printf("  [debug] Elevated (admin): %s\n", is_elevated() ? "YES" : "NO");

    /* Check access BEFORE taking ownership */
    printf("  [debug] Before takeown:\n");
    debug_file_info("DLL file", file_path);

    char dir_path[MAX_PATH];
    strncpy(dir_path, file_path, MAX_PATH - 1);
    dir_path[MAX_PATH - 1] = '\0';
    char *last_sep = strrchr(dir_path, '\\');
    if (!last_sep) last_sep = strrchr(dir_path, '/');
    if (last_sep) *last_sep = '\0';

    debug_file_info("Parent dir", dir_path);

    /* Take ownership of the file itself */
    printf("\n  [debug] Taking ownership of DLL...\n");
    take_ownership(file_path);

    /* Take ownership of parent directory for creating .bak */
    printf("  [debug] Taking ownership of parent dir...\n");
    take_ownership(dir_path);

    /* Check access AFTER taking ownership */
    printf("\n  [debug] After takeown:\n");
    debug_file_info("DLL file", file_path);
    debug_file_info("Parent dir", dir_path);
    printf("  [debug] --- End ownership debug ---\n\n");

    return 0;
}
#endif

/* ── Auto-find amfrtdrv64.dll on Windows ─────────────────────────────── */

#ifdef _WIN32
static const char *auto_find_dll(void) {
    static char found_path[MAX_PATH];
    int total_found = 0;

    printf("  [debug] Searching for amfrtdrv64.dll...\n");

    /* Try System32 first */
    const char *sys32 = "C:\\Windows\\System32\\amfrtdrv64.dll";
    if (GetFileAttributesA(sys32) != INVALID_FILE_ATTRIBUTES) {
        printf("  [debug] Found in System32: %s\n", sys32);
        strncpy(found_path, sys32, MAX_PATH - 1);
        total_found++;
        /* Don't return yet — keep searching to log all copies */
    }

    /* Search DriverStore */
    WIN32_FIND_DATAA fd;
    HANDLE hFind;

    /* Manual search of DriverStore subdirs */
    {
        const char *base = "C:\\Windows\\System32\\DriverStore\\FileRepository";
        char search_pattern[MAX_PATH];
        snprintf(search_pattern, sizeof(search_pattern), "%s\\*", base);

        hFind = FindFirstFileA(search_pattern, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (fd.cFileName[0] == '.') continue;

                /* Search one level deeper */
                char subdir[MAX_PATH];
                snprintf(subdir, sizeof(subdir), "%s\\%s\\*", base, fd.cFileName);

                WIN32_FIND_DATAA fd2;
                HANDLE hFind2 = FindFirstFileA(subdir, &fd2);
                if (hFind2 == INVALID_HANDLE_VALUE) continue;

                do {
                    if (!(fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                    if (fd2.cFileName[0] == '.') continue;

                    char candidate[MAX_PATH];
                    snprintf(candidate, sizeof(candidate), "%s\\%s\\%s\\amfrtdrv64.dll",
                             base, fd.cFileName, fd2.cFileName);

                    if (GetFileAttributesA(candidate) != INVALID_FILE_ATTRIBUTES) {
                        /* Get file size for identification */
                        WIN32_FIND_DATAA finfo;
                        HANDLE hInfo = FindFirstFileA(candidate, &finfo);
                        DWORD file_size = 0;
                        if (hInfo != INVALID_HANDLE_VALUE) {
                            file_size = finfo.nFileSizeLow;
                            FindClose(hInfo);
                        }

                        total_found++;
                        printf("  [debug] Found DLL #%d: %s (%lu bytes)\n",
                               total_found, candidate, (unsigned long)file_size);

                        /* Use the first DriverStore match if we didn't find one in System32 */
                        if (found_path[0] == '\0' || total_found == 1) {
                            strncpy(found_path, candidate, MAX_PATH - 1);
                        }
                    }
                } while (FindNextFileA(hFind2, &fd2));
                FindClose(hFind2);

            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }

    printf("  [debug] Total DLL copies found: %d\n", total_found);
    if (total_found > 1) {
        printf("  [debug] NOTE: Multiple copies found! Using: %s\n", found_path);
        printf("  [debug] If patching doesn't take effect, try specifying the other path manually.\n");
    }

    if (total_found == 0) return NULL;
    return found_path;
}
#endif

/* ── Usage ───────────────────────────────────────────────────────────── */

static void usage(const char *argv0) {
    printf("AMF Split Frame Encode (SFE) File Patcher\n");
    printf("Patches amfrtdrv64.dll to force-enable dual VCN encoding\n\n");
    printf("Usage:\n");
    printf("  %s --verify [path]           Scan and report, no changes\n", argv0);
    printf("  %s --patch [path] -o <out>   Patch and write to output file\n", argv0);
    printf("  %s --replace [path]          Patch in-place (creates .bak backup)\n", argv0);
    printf("\nIf [path] is omitted, auto-searches System32 and DriverStore.\n");
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    enum { MODE_NONE, MODE_VERIFY, MODE_PATCH, MODE_REPLACE } mode = MODE_NONE;
    const char *dll_path = NULL;
    const char *output_path = NULL;

    /* Parse args */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verify") == 0) {
            mode = MODE_VERIFY;
        } else if (strcmp(argv[i], "--patch") == 0) {
            mode = MODE_PATCH;
        } else if (strcmp(argv[i], "--replace") == 0) {
            mode = MODE_REPLACE;
        } else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc) {
            output_path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else if (argv[i][0] != '-') {
            dll_path = argv[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (mode == MODE_NONE) {
        usage(argv[0]);
        return 1;
    }

    if (mode == MODE_PATCH && !output_path) {
        fprintf(stderr, "Error: --patch requires -o <output_path>\n");
        return 1;
    }

    /* Auto-find DLL if path not given */
    if (!dll_path) {
#ifdef _WIN32
        printf("No path specified, searching for amfrtdrv64.dll...\n");
        dll_path = auto_find_dll();
        if (!dll_path) {
            fprintf(stderr, "Error: Could not find amfrtdrv64.dll automatically.\n");
            fprintf(stderr, "Please specify the path manually.\n");
            return 1;
        }
        printf("Found: %s\n", dll_path);
#else
        fprintf(stderr, "Error: No DLL path specified.\n");
        return 1;
#endif
    }

    /* Read the DLL */
    size_t dll_size;
    uint8_t *dll_data = read_file(dll_path, &dll_size);
    if (!dll_data) {
        fprintf(stderr, "Error: Failed to read %s\n", dll_path);
        fprintf(stderr, "\n========================================\n");
        fprintf(stderr, "If reporting this error, please share ALL\n");
        fprintf(stderr, "output above (scroll up to the top).\n");
        fprintf(stderr, "========================================\n");
        return 1;
    }
    printf("Loaded %s (%zu bytes)\n\n", dll_path, dll_size);

    /* Process patch definitions — multiple variants may exist for the same
       logical patch (different driver versions). We need exactly ONE variant
       to match (or be already patched). */
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
        int matches = pattern_scan(dll_data, dll_size, pd->pattern, pd->pattern_len, &match_offset);

        if (matches == 0) {
            /* Check if already patched */
            uint8_t *patched_pattern = (uint8_t *)malloc(pd->pattern_len);
            memcpy(patched_pattern, pd->pattern, pd->pattern_len);
            memcpy(patched_pattern + pd->patch_offset, pd->patch, pd->patch_len);

            int patched_matches = pattern_scan(dll_data, dll_size, patched_pattern, pd->pattern_len, &match_offset);
            free(patched_pattern);

            if (patched_matches == 1) {
                printf("  Status:  ALREADY PATCHED at offset 0x%zX\n", match_offset);
                printf("  Bytes:   ");
                print_hex(dll_data + match_offset, pd->pattern_len);
                printf("\n\n");
                any_hevc_matched = 1;
                continue;
            }

            printf("  Status:  Not found (different driver version)\n\n");
            continue;
        }

        if (matches > 1) {
            fprintf(stderr, "  ERROR:   Pattern found %d times (expected exactly 1). Aborting.\n\n", matches);
            any_error = 1;
            continue;
        }

        size_t patch_addr = match_offset + pd->patch_offset;
        printf("  Found:   1 match at offset 0x%zX\n", match_offset);
        printf("  Patch:   offset 0x%zX: ", patch_addr);
        print_hex(dll_data + patch_addr, pd->patch_len);
        printf("-> ");
        print_hex(pd->patch, pd->patch_len);
        printf("\n");

        any_hevc_matched = 1;

        if (mode != MODE_VERIFY) {
            memcpy(dll_data + patch_addr, pd->patch, pd->patch_len);
            total_patched++;
            printf("  Applied: YES\n");
        } else {
            printf("  Applied: NO (verify mode)\n");
        }
        printf("\n");
    }

    if (any_error) {
        fprintf(stderr, "Errors occurred, aborting without writing.\n");
        free(dll_data);
        return 1;
    }

    if (!any_hevc_matched) {
        fprintf(stderr, "Error: No known HEVC SFE pattern matched this DLL.\n");
        fprintf(stderr, "This driver version may need a new pattern. File size: %zu bytes\n", dll_size);
        fprintf(stderr, "\n========================================\n");
        fprintf(stderr, "If reporting this error, please share ALL\n");
        fprintf(stderr, "output above (scroll up to the top).\n");
        fprintf(stderr, "========================================\n");
        free(dll_data);
        return 1;
    }

    /* Write output */
    if (mode == MODE_VERIFY) {
        printf("Verify complete. No changes written.\n");
    } else if (mode == MODE_PATCH) {
        if (total_patched == 0) {
            printf("Nothing to patch (already patched?).\n");
        } else {
            printf("Writing patched DLL to %s...\n", output_path);
            if (write_file(output_path, dll_data, dll_size) != 0) {
                fprintf(stderr, "Error: Failed to write output file.\n");
                free(dll_data);
                return 1;
            }
            printf("Done. %d patch(es) applied.\n", total_patched);
        }
    } else if (mode == MODE_REPLACE) {
        if (total_patched == 0) {
            printf("Nothing to patch (already patched?).\n");
        } else {
            /* Take ownership if needed (DriverStore is owned by TrustedInstaller) */
#ifdef _WIN32
            printf("Taking ownership of file and directory...\n");
            take_ownership_for_write(dll_path);
#endif

            /* Create backup */
            char bak_path[4096];
            snprintf(bak_path, sizeof(bak_path), "%s.bak", dll_path);
            printf("Creating backup: %s -> %s\n", dll_path, bak_path);
            if (copy_file(dll_path, bak_path) != 0) {
#ifdef _WIN32
                DWORD err = GetLastError();
                fprintf(stderr, "Error: Failed to create backup (GetLastError=%lu", err);
                if (err == 5)  fprintf(stderr, " ACCESS_DENIED");
                if (err == 32) fprintf(stderr, " SHARING_VIOLATION");
                if (err == 3)  fprintf(stderr, " PATH_NOT_FOUND");
                fprintf(stderr, ")\n");
                fprintf(stderr, "  [debug] Backup src: %s\n", dll_path);
                fprintf(stderr, "  [debug] Backup dst: %s\n", bak_path);
                if (err == 32)
                    fprintf(stderr, "  Hint: A process has the DLL locked. Close AMD Software / Apollo / Sunshine and try again.\n");
#else
                fprintf(stderr, "Error: Failed to create backup.\n");
#endif
                fprintf(stderr, "Aborting — original file was NOT modified.\n");
                fprintf(stderr, "\n========================================\n");
                fprintf(stderr, "If reporting this error, please share ALL\n");
                fprintf(stderr, "output above (scroll up to the top).\n");
                fprintf(stderr, "========================================\n");
                free(dll_data);
                return 1;
            }
            printf("  [debug] Backup created successfully (%zu bytes)\n", dll_size);

            printf("Writing patched DLL to %s...\n", dll_path);
            if (write_file(dll_path, dll_data, dll_size) != 0) {
#ifdef _WIN32
                DWORD err = GetLastError();
                fprintf(stderr, "Error: Failed to write patched file (GetLastError=%lu", err);
                if (err == 5)  fprintf(stderr, " ACCESS_DENIED");
                if (err == 32) fprintf(stderr, " SHARING_VIOLATION");
                fprintf(stderr, ")\n");
                if (err == 32)
                    fprintf(stderr, "  Hint: A process has the DLL locked. Close AMD Software / Apollo / Sunshine and try again.\n");
#else
                fprintf(stderr, "Error: Failed to write patched file.\n");
#endif
                fprintf(stderr, "Original backup at: %s\n", bak_path);
                fprintf(stderr, "\n========================================\n");
                fprintf(stderr, "If reporting this error, please share ALL\n");
                fprintf(stderr, "output above (scroll up to the top).\n");
                fprintf(stderr, "========================================\n");
                free(dll_data);
                return 1;
            }
            printf("Done. %d patch(es) applied. Backup at: %s\n", total_patched, bak_path);
        }
    }

    free(dll_data);
    return 0;
}
