/*
 * AMF Split Frame Encode (SFE) Dynamic Patcher
 *
 * Unlike the static patcher, this version doesn't rely on exact byte patterns
 * that break across driver versions. Instead it:
 *
 * 1. Parses the PE structure of amfrtdrv64.dll
 * 2. Finds the "HevcMultiHwInstanceEncode" wide string in .rdata
 * 3. Finds code cross-references (LEA instructions) to that string
 * 4. Uses that as an anchor to locate the dual VCN setup function
 * 5. Applies relaxed wildcard pattern matching within that function
 *
 * This should survive driver updates as long as AMD doesn't fundamentally
 * restructure their encoder initialization code.
 *
 * Build (MSVC):  cl /O2 /W4 amf-sfe-patch-dynamic.c /Fe:amf-sfe-patch-dynamic.exe
 * Build (MinGW): gcc -O2 -Wall -o amf-sfe-patch-dynamic.exe amf-sfe-patch-dynamic.c
 * Cross:         x86_64-w64-mingw32-gcc -O2 -Wall -o amf-sfe-patch-dynamic.exe amf-sfe-patch-dynamic.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#pragma comment(lib, "shlwapi.lib")
#endif

/* ── PE structures (minimal, no windows.h dependency for cross-compile) ── */

#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;
    uint8_t  pad[58];
    uint32_t e_lfanew;
} DOS_Header;

typedef struct {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} PE_Header;

typedef struct {
    /* We only need ImageBase from the optional header */
    uint16_t Magic;
    uint8_t  pad1[22];
    uint64_t ImageBase;       /* offset 24 in optional header for PE32+ */
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint8_t  pad2[72];       /* skip to SizeOfImage at offset 56 */
    /* ... we don't need the rest */
} OptionalHeader64;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLineNumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLineNumbers;
    uint32_t Characteristics;
} SectionHeader;

#pragma pack(pop)

/* ── PE parsing ──────────────────────────────────────────────────────── */

typedef struct {
    uint8_t *data;
    size_t   size;

    /* Parsed from headers */
    uint64_t image_base;
    uint32_t section_alignment;

    /* Sections we care about */
    uint32_t text_file_offset;
    uint32_t text_size;
    uint32_t text_rva;

    SectionHeader *sections;
    uint16_t       num_sections;
} PEFile;

static int pe_parse(PEFile *pe, uint8_t *data, size_t size) {
    memset(pe, 0, sizeof(*pe));
    pe->data = data;
    pe->size = size;

    if (size < sizeof(DOS_Header)) return -1;
    DOS_Header *dos = (DOS_Header *)data;
    if (dos->e_magic != 0x5A4D) return -1; /* "MZ" */

    uint32_t pe_off = dos->e_lfanew;
    if (pe_off + sizeof(PE_Header) > size) return -1;

    PE_Header *peh = (PE_Header *)(data + pe_off);
    if (peh->Signature != 0x00004550) return -1; /* "PE\0\0" */

    if (peh->Machine != 0x8664) {
        fprintf(stderr, "Not a 64-bit PE (machine: 0x%04X)\n", peh->Machine);
        return -1;
    }

    /* Optional header follows PE header */
    uint32_t opt_off = pe_off + sizeof(PE_Header);
    if (opt_off + sizeof(OptionalHeader64) > size) return -1;

    OptionalHeader64 *opt = (OptionalHeader64 *)(data + opt_off);
    if (opt->Magic != 0x20B) {
        fprintf(stderr, "Not PE32+ (magic: 0x%04X)\n", opt->Magic);
        return -1;
    }

    pe->image_base = opt->ImageBase;
    pe->section_alignment = opt->SectionAlignment;

    /* Section headers follow optional header */
    uint32_t sec_off = opt_off + peh->SizeOfOptionalHeader;
    pe->num_sections = peh->NumberOfSections;
    pe->sections = (SectionHeader *)(data + sec_off);

    if (sec_off + pe->num_sections * sizeof(SectionHeader) > size) return -1;

    /* Find .text section */
    for (uint16_t i = 0; i < pe->num_sections; i++) {
        SectionHeader *s = &pe->sections[i];
        if (memcmp(s->Name, ".text", 5) == 0) {
            pe->text_file_offset = s->PointerToRawData;
            pe->text_size = s->SizeOfRawData;
            pe->text_rva = s->VirtualAddress;
            break;
        }
    }

    if (!pe->text_size) {
        fprintf(stderr, "Could not find .text section\n");
        return -1;
    }

    return 0;
}

/* Convert file offset to RVA */
static uint32_t file_to_rva(PEFile *pe, uint32_t file_off) {
    for (uint16_t i = 0; i < pe->num_sections; i++) {
        SectionHeader *s = &pe->sections[i];
        if (file_off >= s->PointerToRawData &&
            file_off < s->PointerToRawData + s->SizeOfRawData) {
            return s->VirtualAddress + (file_off - s->PointerToRawData);
        }
    }
    return 0;
}

/* ── Wildcard pattern matching ───────────────────────────────────────── */

/*
 * Pattern bytes with 0x100+ meaning "wildcard" (match any).
 * We use uint16_t patterns: 0x00-0xFF = exact match, 0xFFFF = wildcard.
 */
#define WILD 0xFFFF

static int wildcard_scan(const uint8_t *data, size_t data_len,
                         const uint16_t *pattern, size_t pattern_len,
                         size_t *match_offset, size_t start_offset) {
    int count = 0;
    if (data_len < pattern_len) return 0;

    for (size_t i = start_offset; i <= data_len - pattern_len; i++) {
        int match = 1;
        for (size_t j = 0; j < pattern_len; j++) {
            if (pattern[j] != WILD && data[i + j] != (uint8_t)pattern[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            if (count == 0 && match_offset)
                *match_offset = i;
            count++;
        }
    }
    return count;
}

/* ── String search ───────────────────────────────────────────────────── */

/* Find a UTF-16LE wide string in the PE file data */
static int find_wide_string(const uint8_t *data, size_t data_len,
                            const char *str, size_t *out_offset) {
    size_t slen = strlen(str);
    size_t wide_len = slen * 2;

    if (data_len < wide_len) return 0;

    for (size_t i = 0; i <= data_len - wide_len; i++) {
        int match = 1;
        for (size_t j = 0; j < slen; j++) {
            if (data[i + j * 2] != (uint8_t)str[j] || data[i + j * 2 + 1] != 0) {
                match = 0;
                break;
            }
        }
        if (match) {
            *out_offset = i;
            return 1;
        }
    }
    return 0;
}

/* ── Find cross-references (LEA reg, [rip+disp32]) ──────────────────── */

/*
 * x86-64 RIP-relative LEA: 48 8D xx yy yy yy yy  or  4C 8D xx yy yy yy yy
 * where xx encodes the register and addressing mode (ModRM with mod=00, r/m=101 for RIP-relative)
 *
 * ModRM byte for [RIP+disp32]: mod=00, r/m=101 → bottom bits = 0bXX000101
 * So ModRM & 0xC7 == 0x05
 */
typedef struct {
    uint32_t file_offset;    /* file offset of the LEA instruction */
    uint32_t target_rva;     /* RVA the LEA points to */
} XRef;

static int find_lea_xrefs(PEFile *pe, uint32_t target_rva,
                          XRef *xrefs, int max_xrefs) {
    int count = 0;
    uint8_t *text = pe->data + pe->text_file_offset;
    uint32_t text_size = pe->text_size;

    for (uint32_t i = 0; i + 7 <= text_size; i++) {
        /* Check for REX.W LEA (48 8D or 4C 8D) */
        uint8_t rex = text[i];
        if (rex != 0x48 && rex != 0x4C) continue;
        if (text[i + 1] != 0x8D) continue;

        uint8_t modrm = text[i + 2];
        /* RIP-relative: mod=00, r/m=101 → (modrm & 0xC7) == 0x05 */
        if ((modrm & 0xC7) != 0x05) continue;

        /* disp32 is at i+3..i+6 */
        int32_t disp = *(int32_t *)(text + i + 3);

        /* RIP-relative: target = RVA_of_next_instruction + disp
           next instruction is at text_rva + i + 7 */
        uint32_t next_rva = pe->text_rva + i + 7;
        uint32_t lea_target = (uint32_t)((int64_t)next_rva + disp);

        if (lea_target == target_rva) {
            if (count < max_xrefs) {
                xrefs[count].file_offset = pe->text_file_offset + i;
                xrefs[count].target_rva = lea_target;
            }
            count++;
        }
    }
    return count;
}

/* ── Find function boundaries ────────────────────────────────────────── */

/*
 * Walk backwards from an offset to find a likely function prologue.
 * Common prologues:
 *   48 89 5C 24 xx   MOV [RSP+xx], RBX
 *   48 89 4C 24 xx   MOV [RSP+xx], RCX
 *   40 53             PUSH RBX
 *   40 55             PUSH RBP
 *   48 83 EC xx       SUB RSP, xx
 *   48 81 EC xx xx xx xx  SUB RSP, xxxx
 *   CC CC CC CC       int3 padding (function boundary)
 *
 * We look for int3 padding (CC bytes) which compilers insert between functions.
 */
static uint32_t find_function_start(const uint8_t *data, uint32_t offset, uint32_t max_search) {
    /* Walk backwards looking for a run of CC bytes (inter-function padding) */
    uint32_t search_start = (offset > max_search) ? offset - max_search : 0;

    for (uint32_t i = offset - 1; i > search_start; i--) {
        if (data[i] == 0xCC && i > 0 && data[i - 1] == 0xCC) {
            /* Found CC padding — function starts right after */
            uint32_t func_start = i + 1;
            while (func_start < offset && data[func_start] == 0xCC)
                func_start++;
            return func_start;
        }
    }
    return search_start;
}

/*
 * Find approximate function end by looking for the next CC CC padding or RET + CC.
 */
static uint32_t find_function_end(const uint8_t *data, size_t data_size,
                                  uint32_t func_start, uint32_t max_size) {
    uint32_t limit = func_start + max_size;
    if (limit > data_size) limit = (uint32_t)data_size;

    for (uint32_t i = func_start + 16; i + 1 < limit; i++) {
        /* C3 CC = RET followed by padding */
        if (data[i] == 0xC3 && data[i + 1] == 0xCC)
            return i + 1;
    }
    return limit;
}

/* ── Dynamic patch strategies ────────────────────────────────────────── */

/*
 * Instead of exact byte patterns, we use structural analysis:
 *
 * 1. RESOLUTION GATE: CMP EAX, 0x7E9000 / JAE — the 4K constant is unique
 *    and stable across all versions. Exact match.
 *
 * 2. HEURISTIC BYPASS: CMP byte [reg+heuristic_offset], 0 / JZ
 *    We discover the heuristic offset by finding CMP byte [reg+disp32], 0 / JZ
 *    instructions within the setup function where the displacement is NOT the
 *    SFE offset — specifically the one with JZ displacement >= 0x20 (long jump
 *    indicating a major branch, not a minor check).
 *
 * 3. WHITELIST BYPASS: We find where the SFE flag is set (MOV byte [reg+sfe], 1)
 *    and look backwards for the conditional check that gates it. Then we NOP
 *    the conditional so the flag is always set.
 *
 * 4. SFE DISABLE WRITES: All MOV byte [reg+sfe_offset], 0 across .text.
 *    Discovered dynamically using the SFE offset from step 2.
 *
 * 5. WHITELIST RE-CHECK: CMP byte [reg+whitelist_offset], 0 / JZ with a far
 *    jump later in the setup function. Discovered using the whitelist offset.
 */

/* Resolution gate — only truly stable exact pattern */
static const uint16_t resolution_pat[] = {
    0x3D, 0x00, 0x90, 0x7E, 0x00,    /* CMP EAX, 0x7E9000 */
    0x73, WILD                        /* JAE +disp8 */
};
/* resolution_fix not needed — we patch the byte directly in the main loop */

/* ── Helpers ─────────────────────────────────────────────────────────── */

static void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%02X ", data[i]);
}

static uint8_t *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

static int write_file(const char *path, const uint8_t *data, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }
    if (fwrite(data, 1, size, f) != size) { perror("fwrite"); fclose(f); return -1; }
    fclose(f);
    return 0;
}

static int copy_file_bytes(const char *src, const char *dst) {
    size_t sz;
    uint8_t *data = read_file(src, &sz);
    if (!data) return -1;
    int r = write_file(dst, data, sz);
    free(data);
    return r;
}

/* ── Auto-find DLL (Windows) ────────────────────────────────────────── */

#ifdef _WIN32
static const char *auto_find_dll(void) {
    static char found_path[MAX_PATH];

    const char *sys32 = "C:\\Windows\\System32\\amfrtdrv64.dll";
    if (GetFileAttributesA(sys32) != INVALID_FILE_ATTRIBUTES) {
        strncpy(found_path, sys32, MAX_PATH - 1);
        return found_path;
    }

    const char *base = "C:\\Windows\\System32\\DriverStore\\FileRepository";
    char search_pattern[MAX_PATH];
    snprintf(search_pattern, sizeof(search_pattern), "%s\\*", base);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search_pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return NULL;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == '.') continue;

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
                FindClose(hFind2);
                FindClose(hFind);
                strncpy(found_path, candidate, MAX_PATH - 1);
                return found_path;
            }
        } while (FindNextFileA(hFind2, &fd2));
        FindClose(hFind2);
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    return NULL;
}
#endif

/* ── Offset discovery ────────────────────────────────────────────────── */

typedef struct {
    uint16_t sfe_offset;       /* e.g., 0xC2C — the SFE enable flag */
    uint16_t sfe_offset2;      /* e.g., 0xC2D — secondary SFE flag (optional) */
    uint16_t whitelist_offset; /* e.g., 0x602 — whitelist flag */
    int have_sfe;
    int have_sfe2;
    int have_whitelist;
} DiscoveredOffsets;

/*
 * Discover struct offsets by scanning the setup function for known instruction patterns.
 *
 * SFE flag: found via MOV byte [reg+disp32], 1 (C6 8x xx xx 00 00 01)
 *   The first such write with a large offset (> 0x100) is the SFE flag.
 *   A second one 1 byte higher is the secondary SFE flag.
 *
 * Whitelist flag: found via MOV byte [reg+disp32], reg (40 88 xx xx xx 00 00)
 *   near a TEST/JNZ or TEST/JZ. We look for conditional MOV byte writes
 *   to struct offsets in the 0x600 range within the setup function.
 *   More reliably: look for CMP byte [reg+disp32], 0 / JZ with a far jump
 *   where the offset is in a "flag-like" range (0x400-0x800).
 */
static void discover_offsets(const uint8_t *func, size_t func_size, DiscoveredOffsets *out) {
    memset(out, 0, sizeof(*out));

    /* Pass 1: Find MOV byte [reg+disp32], 1 — SFE flag enable writes */
    uint16_t sfe_candidates[8];
    int num_sfe = 0;

    for (size_t i = 0; i + 7 <= func_size && num_sfe < 8; i++) {
        if (func[i] != 0xC6) continue;
        uint8_t modrm = func[i + 1];
        /* mod=10 (disp32), reg/opcode=000, r/m = any */
        if ((modrm & 0xC0) != 0x80 || (modrm & 0x38) != 0x00) continue;
        /* High word of disp32 must be 0 */
        if (func[i + 4] != 0x00 || func[i + 5] != 0x00) continue;
        /* imm8 = 1 */
        if (func[i + 6] != 0x01) continue;

        uint16_t offset = *(uint16_t *)(func + i + 2);
        /* SFE offset is typically large (> 0x100), filter out small ones */
        if (offset < 0x100) continue;

        /* Deduplicate */
        int dup = 0;
        for (int j = 0; j < num_sfe; j++)
            if (sfe_candidates[j] == offset) { dup = 1; break; }
        if (!dup)
            sfe_candidates[num_sfe++] = offset;
    }

    if (num_sfe >= 1) {
        out->sfe_offset = sfe_candidates[0];
        out->have_sfe = 1;
        printf("  SFE flag offset:       0x%X\n", out->sfe_offset);
    }
    if (num_sfe >= 2) {
        out->sfe_offset2 = sfe_candidates[1];
        out->have_sfe2 = 1;
        printf("  SFE flag offset (2nd): 0x%X\n", out->sfe_offset2);
    }

    /* Pass 2: Find whitelist offset — look for conditional MOV byte writes
       with REX prefix (40 88 xx xx xx 00 00) to offsets in 0x400-0x900 range */
    for (size_t i = 0; i + 7 <= func_size; i++) {
        if (func[i] != 0x40) continue;
        if (func[i + 1] != 0x88) continue;
        uint8_t modrm = func[i + 2];
        if ((modrm & 0xC0) != 0x80) continue; /* mod=10 disp32 */
        if (func[i + 5] != 0x00 || func[i + 6] != 0x00) continue;

        uint16_t offset = *(uint16_t *)(func + i + 3);
        if (offset >= 0x400 && offset <= 0x900) {
            out->whitelist_offset = offset;
            out->have_whitelist = 1;
            printf("  Whitelist flag offset: 0x%X\n", offset);
            break;
        }
    }

    /* Fallback: look for CMP byte [reg+disp32], 0 with offset in 0x400-0x900 range
       that appears before the SFE enable block */
    if (!out->have_whitelist) {
        for (size_t i = 0; i + 7 <= func_size; i++) {
            if (func[i] != 0x80) continue;
            uint8_t modrm = func[i + 1];
            if ((modrm & 0xC0) != 0x80 || (modrm & 0x38) != 0x38) continue;
            if (func[i + 4] != 0x00 || func[i + 5] != 0x00) continue;
            if (func[i + 6] != 0x00) continue; /* CMP ..., 0 */

            uint16_t offset = *(uint16_t *)(func + i + 2);
            if (offset >= 0x400 && offset <= 0x900) {
                out->whitelist_offset = offset;
                out->have_whitelist = 1;
                printf("  Whitelist flag offset: 0x%X (from CMP)\n", offset);
                break;
            }
        }
    }
}

/*
 * Find the heuristic check within the setup function.
 * Pattern: CMP byte [reg+disp32], 0 / JZ +disp8
 *   80 {modrm} {lo} {hi} 00 00 00 74 {disp8}
 * where modrm has mod=10, reg/opcode=111 (CMP)
 *
 * We identify the RIGHT one by:
 * - It must be inside the setup function
 * - The JZ displacement should be >= 0x20 (it's a major branch, not a trivial skip)
 * - The struct offset should be large (> 0x800) — it's a "heuristic enabled" flag,
 *   separate from the SFE flag and whitelist flag
 */
static int find_and_patch_heuristic(uint8_t *func, size_t func_size,
                                    uint32_t func_file_offset,
                                    const DiscoveredOffsets *offsets,
                                    int apply, int *patched) {
    int found = 0;

    for (size_t i = 0; i + 9 <= func_size; i++) {
        if (func[i] != 0x80) continue;
        uint8_t modrm = func[i + 1];
        /* mod=10 (disp32), reg/opcode=111 (CMP), r/m=any */
        if ((modrm & 0xC0) != 0x80) continue;
        if ((modrm & 0x38) != 0x38) continue;
        /* High word of disp32 = 0 */
        if (func[i + 4] != 0x00 || func[i + 5] != 0x00) continue;
        /* imm8 = 0 */
        if (func[i + 6] != 0x00) continue;
        /* Followed by JZ */
        if (func[i + 7] != 0x74) continue;

        uint16_t offset = *(uint16_t *)(func + i + 2);
        uint8_t jz_disp = func[i + 8];

        /* Filter: must be a large struct offset (heuristic flag, not SFE or whitelist) */
        if (offset < 0x800) continue;
        /* Filter: skip if this is the SFE offset itself */
        if (offsets->have_sfe && offset == offsets->sfe_offset) continue;
        /* Filter: skip if this matches the whitelist offset — let whitelist bypass handle it */
        if (offsets->have_whitelist && offset == offsets->whitelist_offset) continue;
        /* Filter: JZ displacement should be significant (major branch) */
        if (jz_disp < 0x20) continue;

        found++;
        printf("  [Heuristic check] at file 0x%X: ", (uint32_t)(func_file_offset + i));
        print_hex(func + i, 9);
        printf("\n    CMP byte [reg+0x%X], 0 / JZ +0x%X\n", offset, jz_disp);

        if (apply) {
            /* NOP the JZ (2 bytes at offset 7) */
            func[i + 7] = 0x90;
            func[i + 8] = 0x90;
            (*patched)++;
            printf("    -> PATCHED (JZ NOPed)\n");
        } else {
            printf("    -> would NOP JZ\n");
        }
    }
    return found;
}

/*
 * Find and patch the whitelist conditional.
 * In the setup function, there's a conditional write to the whitelist flag offset:
 *   TEST reg, reg / JNZ|JZ +small / MOV byte [reg+wl_offset], reg
 * OR
 *   CMP byte [reg+wl_offset], 0 / JZ +far  (re-check later in function)
 *
 * Strategy: find all conditional jumps (JZ/JNZ) that reference the whitelist offset
 * in nearby instructions, and NOP them to force the whitelist flag to be set.
 */
static int find_and_patch_whitelist(uint8_t *func, size_t func_size,
                                    uint32_t func_file_offset,
                                    const DiscoveredOffsets *offsets,
                                    int apply, int *patched) {
    if (!offsets->have_whitelist) return 0;

    int found = 0;
    uint8_t wl_lo = offsets->whitelist_offset & 0xFF;
    uint8_t wl_hi = (offsets->whitelist_offset >> 8) & 0xFF;

    /* Type 1: Find conditional MOV to whitelist offset.
       Look for the MOV byte [reg+wl_offset], reg instruction and patch the
       conditional jump before it to be unconditional. */
    for (size_t i = 0; i + 11 <= func_size; i++) {
        /* Look for MOV byte [reg+disp32], reg with REX prefix: 40 88 xx xx xx 00 00 */
        if (func[i] != 0x40 || func[i + 1] != 0x88) continue;
        uint8_t modrm = func[i + 2];
        if ((modrm & 0xC0) != 0x80) continue;
        if (func[i + 3] != wl_lo || func[i + 4] != wl_hi) continue;
        if (func[i + 5] != 0x00 || func[i + 6] != 0x00) continue;

        /* Found the MOV. Now look backwards for a TEST/JZ or TEST/JNZ within 10 bytes */
        for (size_t back = 2; back <= 10 && back <= i; back++) {
            size_t ji = i - back;
            /* JZ (74) or JNZ (75) */
            if (func[ji] != 0x74 && func[ji] != 0x75) continue;
            uint8_t jmp_disp = func[ji + 1];
            /* The jump should skip over the MOV (small displacement) */
            if (jmp_disp > 20) continue;

            found++;
            printf("  [Whitelist conditional] at file 0x%X: ", (uint32_t)(func_file_offset + ji));
            printf("%s +0x%X before MOV byte [reg+0x%X]\n",
                   func[ji] == 0x74 ? "JZ" : "JNZ", jmp_disp, offsets->whitelist_offset);
            print_hex(func + ji, (i + 7) - ji);
            printf("\n");

            if (apply) {
                /* NOP the conditional jump (2 bytes) */
                func[ji] = 0x90;
                func[ji + 1] = 0x90;
                (*patched)++;
                printf("    -> PATCHED (conditional jump NOPed, MOV always executes)\n");
            } else {
                printf("    -> would NOP conditional jump\n");
            }
            break;
        }
    }

    /* Type 2: Find CMP byte [reg+wl_offset], 0 / JZ|JE with far jump (re-check).
       80 {modrm} {wl_lo} {wl_hi} 00 00 00 0F 84 xx xx xx xx  (JZ rel32)
       or
       80 {modrm} {wl_lo} {wl_hi} 00 00 00 74 xx              (JZ rel8) */
    for (size_t i = 0; i + 9 <= func_size; i++) {
        if (func[i] != 0x80) continue;
        uint8_t modrm = func[i + 1];
        if ((modrm & 0xC0) != 0x80 || (modrm & 0x38) != 0x38) continue;
        if (func[i + 2] != wl_lo || func[i + 3] != wl_hi) continue;
        if (func[i + 4] != 0x00 || func[i + 5] != 0x00) continue;
        if (func[i + 6] != 0x00) continue;

        /* Check for JZ (near: 0F 84, or short: 74) */
        size_t jmp_off = i + 7;
        int is_jz = 0;
        size_t jmp_len = 0;

        if (jmp_off + 6 <= func_size && func[jmp_off] == 0x0F && func[jmp_off + 1] == 0x84) {
            is_jz = 1;
            jmp_len = 6; /* 0F 84 xx xx xx xx */
        } else if (jmp_off + 2 <= func_size && func[jmp_off] == 0x74) {
            is_jz = 1;
            jmp_len = 2;
        }

        if (!is_jz) continue;

        found++;
        printf("  [Whitelist re-check] at file 0x%X: ", (uint32_t)(func_file_offset + i));
        printf("CMP byte [reg+0x%X], 0 / JZ\n", offsets->whitelist_offset);
        print_hex(func + i, 7 + jmp_len);
        printf("\n");

        if (apply) {
            memset(func + jmp_off, 0x90, jmp_len);
            (*patched)++;
            printf("    -> PATCHED (JZ NOPed)\n");
        } else {
            printf("    -> would NOP JZ\n");
        }
    }

    return found;
}

/*
 * Find and NOP all writes of 0 to the SFE flag offset(s) across .text.
 * These are the various conditions that disable SFE after it was enabled.
 *
 * Patterns:
 *   C6 {modrm} {lo} {hi} 00 00 00  — MOV byte [reg+disp32], 0 (7 bytes)
 *   40 88 {modrm} {lo} {hi} 00 00  — MOV byte [reg+disp32], reg (7 bytes, REX prefix)
 *                                     where source reg contains 0
 */
static int find_and_patch_sfe_disables(uint8_t *text, size_t text_size,
                                       const DiscoveredOffsets *offsets,
                                       int apply, int *patched) {
    int found = 0;

    /* Check both SFE offsets */
    uint16_t check_offsets[2];
    int num_check = 0;
    if (offsets->have_sfe) check_offsets[num_check++] = offsets->sfe_offset;
    if (offsets->have_sfe2) check_offsets[num_check++] = offsets->sfe_offset2;

    for (int c = 0; c < num_check; c++) {
        uint8_t lo = check_offsets[c] & 0xFF;
        uint8_t hi = (check_offsets[c] >> 8) & 0xFF;

        /* Pattern A: C6 {modrm} {lo} {hi} 00 00 00 — MOV byte [reg+disp32], 0 */
        for (size_t i = 0; i + 7 <= text_size; i++) {
            if (text[i] != 0xC6) continue;
            uint8_t modrm = text[i + 1];
            if ((modrm & 0xC0) != 0x80) continue;  /* mod=10 */
            if ((modrm & 0x38) != 0x00) continue;  /* reg/opcode=000 */
            if (text[i + 2] != lo || text[i + 3] != hi) continue;
            if (text[i + 4] != 0x00 || text[i + 5] != 0x00) continue;
            if (text[i + 6] != 0x00) continue;     /* imm8 = 0 */

            found++;
            printf("  [SFE disable #%d] .text+0x%zX: ", found, i);
            print_hex(text + i, 7);
            printf(" (MOV byte [reg+0x%X], 0)\n", check_offsets[c]);

            if (apply) {
                memset(text + i, 0x90, 7);
                (*patched)++;
                printf("    -> NOPed\n");
            } else {
                printf("    -> would NOP\n");
            }
        }

        /* Pattern B: 40 88 {modrm} {lo} {hi} 00 00 — MOV [reg+disp32], reg (REX) */
        for (size_t i = 0; i + 7 <= text_size; i++) {
            if (text[i] != 0x40) continue;
            if (text[i + 1] != 0x88) continue;
            uint8_t modrm = text[i + 2];
            if ((modrm & 0xC0) != 0x80) continue;
            if (text[i + 3] != lo || text[i + 4] != hi) continue;
            if (text[i + 5] != 0x00 || text[i + 6] != 0x00) continue;

            found++;
            printf("  [SFE disable #%d] .text+0x%zX: ", found, i);
            print_hex(text + i, 7);
            printf(" (MOV byte [reg+0x%X], reg)\n", check_offsets[c]);

            if (apply) {
                memset(text + i, 0x90, 7);
                (*patched)++;
                printf("    -> NOPed\n");
            } else {
                printf("    -> would NOP\n");
            }
        }

        /* Pattern C: CMP byte [reg+disp32], 0 / JZ — conditional check on SFE flag
           These gate the SFE code path later. NOP the JZ so it always falls through.
           80 {modrm:mod=10,reg=111} {lo} {hi} 00 00 00 {74|0F 84} */
        for (size_t i = 0; i + 9 <= text_size; i++) {
            if (text[i] != 0x80) continue;
            uint8_t modrm = text[i + 1];
            if ((modrm & 0xC0) != 0x80 || (modrm & 0x38) != 0x38) continue;
            if (text[i + 2] != lo || text[i + 3] != hi) continue;
            if (text[i + 4] != 0x00 || text[i + 5] != 0x00) continue;
            if (text[i + 6] != 0x00) continue;

            /* Must be followed by JZ */
            size_t j = i + 7;
            int has_jz = 0;
            size_t jz_len = 0;
            if (j + 2 <= text_size && text[j] == 0x74) {
                /* Only patch if the jump skips a significant block (>= 0x20 bytes) */
                if (text[j + 1] >= 0x20) { has_jz = 1; jz_len = 2; }
            } else if (j + 6 <= text_size && text[j] == 0x0F && text[j + 1] == 0x84) {
                has_jz = 1; jz_len = 6;
            }

            if (!has_jz) continue;

            found++;
            printf("  [SFE gate check #%d] .text+0x%zX: ", found, i);
            print_hex(text + i, 7 + jz_len);
            printf(" (CMP byte [reg+0x%X], 0 / JZ)\n", check_offsets[c]);

            if (apply) {
                memset(text + j, 0x90, jz_len);
                (*patched)++;
                printf("    -> JZ NOPed\n");
            } else {
                printf("    -> would NOP JZ\n");
            }
        }
    }

    return found;
}

/* ── Admin check (Windows) ────────────────────────────────────────── */

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
#endif

/* ── Main ────────────────────────────────────────────────────────────── */

static void usage(const char *argv0) {
    printf("AMF Split Frame Encode (SFE) Dynamic Patcher\n");
    printf("Dynamically finds and patches SFE restrictions in amfrtdrv64.dll\n\n");
    printf("Usage:\n");
    printf("  %s --analyze [path]          Deep scan and report, no changes\n", argv0);
    printf("  %s --patch [path] -o <out>   Patch and write to output file\n", argv0);
    printf("  %s --replace [path]          Patch in-place (creates .bak backup)\n", argv0);
    printf("\nIf [path] is omitted on Windows, auto-searches System32 and DriverStore.\n");
}

int main(int argc, char **argv) {
    enum { MODE_NONE, MODE_ANALYZE, MODE_PATCH, MODE_REPLACE } mode = MODE_NONE;
    const char *dll_path = NULL;
    const char *output_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--analyze") == 0) mode = MODE_ANALYZE;
        else if (strcmp(argv[i], "--patch") == 0) mode = MODE_PATCH;
        else if (strcmp(argv[i], "--replace") == 0) mode = MODE_REPLACE;
        else if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) && i + 1 < argc)
            output_path = argv[++i];
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]); return 0;
        } else if (argv[i][0] != '-') dll_path = argv[i];
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); usage(argv[0]); return 1; }
    }

    if (mode == MODE_NONE) { usage(argv[0]); return 1; }
    if (mode == MODE_PATCH && !output_path) {
        fprintf(stderr, "Error: --patch requires -o <output_path>\n"); return 1;
    }

#ifdef _WIN32
    if (mode == MODE_REPLACE && !is_elevated()) {
        fprintf(stderr, "Error: --replace requires Administrator privileges.\n");
        fprintf(stderr, "Right-click Command Prompt or PowerShell and select \"Run as administrator\".\n");
        return 1;
    }
#endif

    if (!dll_path) {
#ifdef _WIN32
        printf("No path specified, searching for amfrtdrv64.dll...\n");
        dll_path = auto_find_dll();
        if (!dll_path) {
            fprintf(stderr, "Error: Could not find amfrtdrv64.dll automatically.\n");
            return 1;
        }
        printf("Found: %s\n", dll_path);
#else
        fprintf(stderr, "Error: No DLL path specified.\n"); return 1;
#endif
    }

    /* Load and parse PE */
    size_t dll_size;
    uint8_t *dll_data = read_file(dll_path, &dll_size);
    if (!dll_data) { fprintf(stderr, "Error: Failed to read %s\n", dll_path); return 1; }
    printf("Loaded %s (%zu bytes)\n", dll_path, dll_size);
    fflush(stdout);

    PEFile pe;
    if (pe_parse(&pe, dll_data, dll_size) != 0) {
        fprintf(stderr, "Error: Not a valid 64-bit PE file.\n");
        fprintf(stderr, "Make sure you're pointing at amfrtdrv64.dll, not a shortcut or other file.\n");
        free(dll_data); return 1;
    }
    printf("PE parsed: .text at file 0x%X (RVA 0x%X), size 0x%X\n",
           pe.text_file_offset, pe.text_rva, pe.text_size);

    /* ── Step 1: Find the anchor string ── */
    printf("\n=== Step 1: Finding HevcMultiHwInstanceEncode string ===\n");

    size_t string_file_offset = 0;
    if (!find_wide_string(dll_data, dll_size, "HevcMultiHwInstanceEncode", &string_file_offset)) {
        fprintf(stderr, "Error: Could not find HevcMultiHwInstanceEncode string.\n");
        fprintf(stderr, "This DLL may not support split frame encoding at all.\n");
        free(dll_data); return 1;
    }

    uint32_t string_rva = file_to_rva(&pe, (uint32_t)string_file_offset);
    printf("Found at file offset 0x%zX (RVA 0x%X)\n", string_file_offset, string_rva);

    /* ── Step 2: Find cross-references to the string ── */
    printf("\n=== Step 2: Finding code references to anchor string ===\n");

    XRef xrefs[16];
    int num_xrefs = find_lea_xrefs(&pe, string_rva, xrefs, 16);

    if (num_xrefs == 0) {
        fprintf(stderr, "Error: No code references found to HevcMultiHwInstanceEncode.\n");
        free(dll_data); return 1;
    }

    printf("Found %d cross-reference(s):\n", num_xrefs);
    for (int i = 0; i < num_xrefs && i < 16; i++)
        printf("  [%d] LEA at file 0x%X\n", i + 1, xrefs[i].file_offset);

    /* ── Step 3: Identify the SFE setup function ── */
    printf("\n=== Step 3: Identifying SFE setup function ===\n");

    uint32_t xref_offset = xrefs[0].file_offset;
    uint32_t func_start = find_function_start(dll_data, xref_offset, 0x2000);
    uint32_t func_end = find_function_end(dll_data, dll_size, func_start, 0x2000);

    printf("Setup function: file 0x%X — 0x%X (%u bytes)\n",
           func_start, func_end, func_end - func_start);

    uint8_t *func_data = dll_data + func_start;
    size_t func_size = func_end - func_start;

    /* ── Step 4: Discover struct offsets ── */
    printf("\n=== Step 4: Discovering struct offsets ===\n");

    DiscoveredOffsets offsets;
    discover_offsets(func_data, func_size, &offsets);

    if (!offsets.have_sfe) {
        fprintf(stderr, "Error: Could not discover SFE flag offset.\n");
        fprintf(stderr, "Cannot proceed — the setup function structure is unrecognized.\n");
        free(dll_data); return 1;
    }

    /* ── Step 5: Apply all patches ── */
    printf("\n=== Step 5: Applying patches ===\n\n");

    int apply = (mode != MODE_ANALYZE);
    int total_patched = 0;
    int any_found = 0;

    /* 5a: Resolution gate (exact pattern, global search) */
    printf("[Resolution gate bypass]\n");
    printf("  Removes 4K minimum resolution check (CMP EAX, 0x7E9000)\n");
    {
        uint8_t *text = dll_data + pe.text_file_offset;
        size_t text_size = pe.text_size;
        size_t off = 0;
        int res_found = 0;

        while (off + 7 <= text_size) {
            int m = wildcard_scan(text, text_size, resolution_pat,
                                  sizeof(resolution_pat) / sizeof(resolution_pat[0]),
                                  &off, off);
            if (m == 0) break;

            res_found++;
            any_found = 1;
            printf("  Match at file 0x%X: ", (uint32_t)(pe.text_file_offset + off));
            print_hex(text + off, 7);
            printf("\n");

            if (apply) {
                text[off + 5] = 0xEB; /* JAE -> JMP */
                total_patched++;
                printf("    -> PATCHED (JAE -> JMP)\n");
            } else {
                printf("    -> would patch\n");
            }
            off++;
        }
        if (!res_found) printf("  NOT FOUND\n");
    }
    printf("\n");

    /* 5b: Heuristic bypass (within setup function) */
    printf("[Heuristic bypass]\n");
    printf("  Removes heuristic check that decides SFE isn't needed\n");
    {
        int h = find_and_patch_heuristic(func_data, func_size, func_start,
                                         &offsets, apply, &total_patched);
        if (h > 0) any_found = 1;
        else if (offsets.have_whitelist && offsets.whitelist_offset >= 0x800)
            printf("  Merged with whitelist check (same offset 0x%X)\n", offsets.whitelist_offset);
        else printf("  NOT FOUND\n");
    }
    printf("\n");

    /* 5c: Whitelist bypass (within setup function) */
    printf("[Whitelist bypass]\n");
    printf("  Forces whitelist flag so SFE is allowed on all devices\n");
    {
        int w = find_and_patch_whitelist(func_data, func_size, func_start,
                                         &offsets, apply, &total_patched);
        if (w > 0) any_found = 1;
        else printf("  NOT FOUND (whitelist offset: %s)\n",
                    offsets.have_whitelist ? "discovered but no conditional found" : "not discovered");
    }
    printf("\n");

    /* 5d: SFE disable writes (global .text search) */
    printf("[SFE disable write removal]\n");
    printf("  NOPing all code that disables SFE flag (offset 0x%X", offsets.sfe_offset);
    if (offsets.have_sfe2) printf(", 0x%X", offsets.sfe_offset2);
    printf(")\n");
    {
        uint8_t *text = dll_data + pe.text_file_offset;
        int d = find_and_patch_sfe_disables(text, pe.text_size, &offsets,
                                            apply, &total_patched);
        if (d > 0) any_found = 1;
        else printf("  No disable writes found\n");
    }
    printf("\n");

    /* ── Summary and output ── */
    printf("=== Summary: %d patch(es) %s ===\n",
           total_patched, apply ? "applied" : "identified");

    if (mode == MODE_ANALYZE) {
        if (any_found)
            printf("This DLL appears patchable. Use --replace to apply.\n");
        else
            printf("No patchable patterns found. This DLL may already be patched,\n"
                   "or it uses an unrecognized structure. Run --analyze on an\n"
                   "unpatched DLL or open an issue with this output.\n");
    } else if (mode == MODE_PATCH) {
        if (total_patched == 0) {
            printf("Nothing to patch (already patched?).\n");
        } else {
            printf("Writing patched DLL to %s...\n", output_path);
            if (write_file(output_path, dll_data, dll_size) != 0) {
                free(dll_data); return 1;
            }
            printf("Done.\n");
        }
    } else if (mode == MODE_REPLACE) {
        if (total_patched == 0) {
            printf("Nothing to patch (already patched?).\n");
        } else {
            char bak_path[4096];
            snprintf(bak_path, sizeof(bak_path), "%s.bak", dll_path);
            printf("Creating backup: %s\n", bak_path);
            if (copy_file_bytes(dll_path, bak_path) != 0) {
                fprintf(stderr, "Error: Failed to create backup.\n");
                free(dll_data); return 1;
            }
            printf("Writing patched DLL...\n");
            if (write_file(dll_path, dll_data, dll_size) != 0) {
                free(dll_data); return 1;
            }
            printf("Done. Backup at: %s\n", bak_path);
        }
    }

    free(dll_data);
    return 0;
}
