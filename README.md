# AMF Split Frame Encode (SFE) Patcher

Force-enable AMD's dual VCN split frame encoding at any resolution. AMD locks SFE behind a 4K+ resolution gate and a device whitelist — this tool removes those restrictions so you can use dual VCN at 1440p (or whatever you want).

## What is SFE?

Split Frame Encoding splits each video frame across both VCN (Video Core Next) encoder instances on supported AMD GPUs, cutting encode latency roughly in half. AMD artificially restricts this to 4K+ resolutions, but the hardware works fine at lower resolutions.

## What this does

The patcher removes the following restrictions from `amfrtdrv64.dll` (AMD's encoder driver):

- **Resolution gate** — removes the 4K minimum (`width * height >= 0x7E9000`) check
- **Heuristic bypass** — removes the check that decides SFE "isn't needed"
- **Device whitelist bypass** — forces the SFE enable flag on all devices
- **SFE disable writes** — NOPs code paths that turn SFE off based on encoder settings

## Three tools

### `amf-sfe-patch-dynamic.exe` — Dynamic patcher (recommended)

Works across driver versions by analyzing the DLL structure at runtime instead of relying on hardcoded byte patterns. Parses the PE, finds the SFE setup function via string references, discovers struct offsets dynamically, then patches.

```
amf-sfe-patch-dynamic.exe --analyze            # deep scan and report, no changes
amf-sfe-patch-dynamic.exe --replace            # patch in-place (creates .bak backup)
amf-sfe-patch-dynamic.exe --patch -o out.dll   # patch to a new file
```

Run `--analyze` first to see what it finds before committing to a patch.

### `amf-sfe-patch.exe` — Static file patcher

Uses exact byte patterns for known driver versions. Faster and simpler, but only works on tested drivers.

```
amf-sfe-patch.exe --verify              # scan only, no changes
amf-sfe-patch.exe --replace             # patch in-place (creates .bak backup)
amf-sfe-patch.exe --patch -o out.dll    # patch to a new file
```

### `amf-sfe-launch.exe` — Runtime memory patcher

Patches a running process's memory without touching the DLL on disk. Uses the same static patterns as `amf-sfe-patch.exe`.

```
amf-sfe-launch.exe --wait sunshine.exe     # wait for process, then patch
amf-sfe-launch.exe --pid 12345             # attach to running PID
amf-sfe-launch.exe "C:\path\to\app.exe"   # launch and patch
```

## Quick start

1. Download `amf-sfe-patch-dynamic.exe` from [Releases](../../releases)
2. Open an admin Command Prompt
3. Run: `amf-sfe-patch-dynamic.exe --analyze`
4. Check the output — it should find your DLL and list all patch sites
5. If it looks good: `amf-sfe-patch-dynamic.exe --replace`
6. Restart your streaming server (Sunshine/Apollo/Vibepollo)

To revert: restore the `.bak` file or reinstall your AMD drivers.

## Compatibility

- **Requires:** AMD GPU with dual VCN hardware (e.g., Radeon RX 7000 series, Radeon 8060S / Strix Halo)
- **Tested on:** Radeon 8060S (Strix Halo, device ID 0x1586) at 1440p
- **Codec results:**
  - AV1 + HDR: **works perfectly** — no artifacts, good quality
  - HEVC + SDR: **works well** — clean image
  - HEVC + HDR: **broken** — fuzzy artifacts at any bitrate, appears to be inherent to AMD's HEVC SFE with 10-bit
- **Recommendation:** Use **AV1 + HDR** with SFE

## Driver version support

**Dynamic patcher** (`amf-sfe-patch-dynamic.exe`): Should work on any driver version as long as AMD keeps the `HevcMultiHwInstanceEncode` string and the same general function structure. It discovers all offsets at runtime — no hardcoded patterns.

**Static patcher** (`amf-sfe-patch.exe` / `amf-sfe-launch.exe`): Confirmed for:
- **Adrenalin 25.3.1** (latest as of April 2026) — `u0198975` driver package
- **Older driver** — `u0420529` driver package

If neither tool works on your driver, run `amf-sfe-patch-dynamic.exe --analyze` and [open an issue](../../issues) with the full output and your driver version.

## How the dynamic patcher works

Instead of hardcoded byte patterns that break across driver updates, the dynamic patcher uses structural analysis:

1. **Parse PE** — reads the DLL's section headers to find `.text` (code) and data sections
2. **Find anchor string** — locates the `"HevcMultiHwInstanceEncode"` UTF-16 wide string in the data section
3. **Follow cross-references** — scans `.text` for `LEA` instructions that reference the string's RVA, giving us the SFE setup function
4. **Discover struct offsets** — within the setup function, finds `MOV byte [reg+offset], 1` instructions to discover the SFE flag offset (e.g., `0xC2C` in current drivers), and conditional writes to find the whitelist flag offset (e.g., `0x602`)
5. **Patch by structure** — uses the discovered offsets to find and NOP:
   - Resolution gate: `CMP EAX, 0x7E9000` (4K pixel count constant)
   - Heuristic check: `CMP byte [reg+heuristic_offset], 0 / JZ` with large jump displacement
   - Whitelist conditional: `JNZ`/`JZ` before `MOV byte [reg+whitelist_offset]`
   - SFE disable writes: all `MOV byte [reg+sfe_offset], 0` across the entire `.text` section

This approach is resilient to changes in register allocation, struct layout, and instruction ordering — as long as the logical structure of AMD's encoder init code remains the same.

## Building

### Windows (MSVC)
```bat
cl /O2 /W4 amf-sfe-patch-dynamic.c /Fe:amf-sfe-patch-dynamic.exe
cl /O2 /W4 amf-sfe-patch.c /Fe:amf-sfe-patch.exe
cl /O2 /W4 amf-sfe-launch.c /Fe:amf-sfe-launch.exe advapi32.lib psapi.lib
```

### Windows (MinGW)
```bat
gcc -O2 -Wall -o amf-sfe-patch-dynamic.exe amf-sfe-patch-dynamic.c
gcc -O2 -Wall -o amf-sfe-patch.exe amf-sfe-patch.c
gcc -O2 -Wall -o amf-sfe-launch.exe amf-sfe-launch.c -lpsapi
```

### Cross-compile from Linux
```bash
x86_64-w64-mingw32-gcc -O2 -Wall -o amf-sfe-patch-dynamic.exe amf-sfe-patch-dynamic.c
x86_64-w64-mingw32-gcc -O2 -Wall -o amf-sfe-patch.exe amf-sfe-patch.c
x86_64-w64-mingw32-gcc -O2 -Wall -o amf-sfe-launch.exe amf-sfe-launch.c -lpsapi
```

Or just run `build.bat` from a Visual Studio Developer Command Prompt or MinGW shell.

## Disclaimer

This modifies AMD driver binaries. Use at your own risk. The file patcher creates `.bak` backups automatically. If something goes wrong, restore the backup or reinstall your AMD drivers.

## License

MIT
