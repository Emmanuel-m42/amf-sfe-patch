# AMF Split Frame Encode (SFE) Patcher

Force-enable AMD's dual VCN split frame encoding at any resolution. AMD locks SFE behind a 4K+ resolution gate and a device whitelist — this tool removes those restrictions so you can use dual VCN at 1440p (or whatever you want).

## What is SFE?

Split Frame Encoding splits each video frame across both VCN (Video Core Next) encoder instances on supported AMD GPUs, cutting encode latency roughly in half. AMD artificially restricts this to 4K+ resolutions, but the hardware works fine at lower resolutions.

## What this does

The patcher finds specific byte patterns in `amfrtdrv64.dll` (AMD's encoder driver) and NOPs out:

- **Heuristic bypass** — removes the check that decides SFE isn't needed
- **Device whitelist bypass** — forces the SFE enable flag to 1 unconditionally
- **VCN instance count bypass** — skips the check requiring 2+ VCN instances (future-proofing)

Pattern matching means it works across multiple driver versions — no hardcoded offsets.

## Two tools

### `amf-sfe-patch.exe` — File patcher
Patches `amfrtdrv64.dll` on disk. Auto-finds the DLL in System32 and DriverStore.

```
amf-sfe-patch.exe --verify              # scan only, no changes
amf-sfe-patch.exe --replace             # patch in-place (creates .bak backup)
amf-sfe-patch.exe --patch -o out.dll    # patch to a new file
```

### `amf-sfe-launch.exe` — Runtime memory patcher
Patches a running process's memory without touching the DLL on disk.

```
amf-sfe-launch.exe --wait sunshine.exe     # wait for process, then patch
amf-sfe-launch.exe --pid 12345             # attach to running PID
amf-sfe-launch.exe "C:\path\to\app.exe"   # launch and patch
```

## Compatibility

- **Requires:** AMD GPU with dual VCN hardware (e.g., Radeon RX 7000 series, Radeon 8060S / Strix Halo)
- **Tested on:** Radeon 8060S (Strix Halo, device ID 0x1586) at 1440p
- **Codec results:**
  - AV1 + HDR: **works perfectly** — no artifacts, good quality
  - HEVC + SDR: **works well** — clean image
  - HEVC + HDR: **broken** — fuzzy artifacts at any bitrate, appears to be inherent to AMD's HEVC SFE with 10-bit
- **Recommendation:** Use **AV1 + HDR** with SFE

## Building

### Windows (MSVC)
```bat
cl /O2 /W4 amf-sfe-patch.c /Fe:amf-sfe-patch.exe
cl /O2 /W4 amf-sfe-launch.c /Fe:amf-sfe-launch.exe advapi32.lib psapi.lib
```

### Windows (MinGW)
```bat
gcc -O2 -Wall -o amf-sfe-patch.exe amf-sfe-patch.c
gcc -O2 -Wall -o amf-sfe-launch.exe amf-sfe-launch.c -lpsapi
```

### Cross-compile from Linux
```bash
x86_64-w64-mingw32-gcc -O2 -Wall -o amf-sfe-patch.exe amf-sfe-patch.c
x86_64-w64-mingw32-gcc -O2 -Wall -o amf-sfe-launch.exe amf-sfe-launch.c -lpsapi
```

Or just run `build.bat` from a Visual Studio Developer Command Prompt or MinGW shell.

## How it works (RE details)

The SFE flag lives at an offset within AMD's encoder object (`+0x600` in newer drivers, `+0x4A0` in older ones). Multiple code paths can disable it:

1. A heuristic function checks if SFE is "worth it" based on resolution — `CMP [reg+offset], 0 / JZ` → NOPed
2. The dual VCN setup function checks a device ID whitelist before enabling split encoding → forced to `MOV [RSI], 1`
3. A resolution gate checks if `width * height >= 0x7E9000` (~4K) → bypassed
4. Multiple HEVC/AV1 feature checks can individually disable SFE (PreAnalysis, FillerData, OutputMode, etc.)

The patcher carries patterns for two known driver versions and will report "not found" cleanly if yours doesn't match.

## Disclaimer

This modifies AMD driver binaries. Use at your own risk. The file patcher creates `.bak` backups automatically. If something goes wrong, restore the backup or reinstall your AMD drivers.

## License

MIT
