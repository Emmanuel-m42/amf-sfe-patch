# AMF Split Frame Encode (SFE) Patcher

Force-enable split frame encoding for AMD GPUs in [Sunshine](https://github.com/LizardByte/Sunshine), [Apollo](https://github.com/ClassicOldSong/Apollo), and [Vibepollo](https://github.com/ClassicOldSong/Apollo) game streaming.

NVIDIA initially had the same 4K+ resolution gate on split encoding, but opened it up in Video Codec SDK 12.1 (May 2023) with a force-enable API. Streaming servers like [Vibepollo](https://github.com/Nonary/Vibepollo) now expose this as a simple toggle for NVENC users. AMD has the same dual-encoder hardware capability on supported GPUs, but still locks SFE behind a 4K resolution gate with no user-facing option or API to override it. **This tool removes that restriction** so you can use split frame encoding at 1440p, 1080p, or whatever resolution you stream at. Ideally AMD adds a force-enable flag to AMF like NVIDIA did, making this tool obsolete. Until then, this is the only way to get SFE working at sub-4K resolutions.

> **Important:** This only works on AMD GPUs that have **two VCN encoder instances** in hardware. If your GPU has a single VCN instance, there is no second encoder to split across. Check the [compatibility table](#supported-hardware) below before using this tool.

## Why this matters

Game streaming is a latency race. At 120 fps, you have **8.33 ms per frame**. That's your entire budget to capture, encode, transmit, decode, and display. At 240 fps, it's just 4.17 ms. Every millisecond the encoder spends on a frame is a millisecond added to the glass-to-glass latency you feel on the controller.

A single VCN instance encoding a 1440p frame might take 4 to 6 ms. Split that across two VCN instances and you're looking at 2 to 3 ms, shaving roughly half the encode time off every single frame. That doesn't sound like much until you realize it's **25 to 35% of your entire frame budget at 120 fps**. Over a network where you're already fighting transport jitter and decode time, that headroom is the difference between a stream that feels local and one that feels sluggish.

NVIDIA opened up this capability in SDK 12.1 back in 2023. If you have an AMD GPU with dual VCN hardware, there's no reason you shouldn't be able to use it the same way.

## Supported hardware

Split frame encoding requires **two VCN instances**. Not all AMD GPUs have this. Many recent GPUs, including all of RDNA 4, only have one.

### Dual VCN GPUs (SFE works)

| GPU | Chip | VCN | HEVC SFE | AV1 SFE | Notes |
|-----|------|-----|----------|---------|-------|
| **Ryzen AI Max (Strix Halo)** | Strix Halo | 5.0 x2 | Yes | **Yes** | Only AMD chip with dual AV1 encode. Best SFE experience. |
| **RX 7900 XTX / 7900 XT / 7900 GRE** | Navi 31 | 4.0 x2 | Yes | No (only 1 AV1 encoder) | HEVC SFE only. Use SDR (HEVC + HDR has artifacts). |
| **RX 7800 XT / 7700 XT** | Navi 32 | 4.0 x2 | Yes | No (only 1 AV1 encoder) | HEVC SFE only. Use SDR. |
| **RX 6900 XT / 6800 XT / 6800** | Navi 21 | 3.0 x2 | Yes | No AV1 encode | HEVC SFE only. No AV1 at all on VCN 3.0. |

### Single VCN GPUs (SFE not possible)

| GPU | Chip | VCN | Why not |
|-----|------|-----|---------|
| **RX 9070 XT / 9070** | Navi 48 | 5.0 x1 | RDNA 4 has only 1 VCN instance |
| **RX 7600 XT / 7600** | Navi 33 | 4.0 x1 | Single VCN |
| **RX 6700 XT / 6750 XT** | Navi 22 | 3.0 x1 | Single VCN |
| **RX 6600 XT / 6600** | Navi 23 | 3.0 x1 | Single VCN |
| **Ryzen AI 9 HX (Strix Point)** | Strix Point | 4.0 x1 | Single VCN |
| **Ryzen 8040 / 7040 APUs** | Hawk Point / Phoenix | 4.0 x1 | Single VCN |

### Codec recommendations

| Your GPU | Codec | HDR | SFE Result |
|----------|-------|-----|------------|
| Strix Halo | AV1 | Yes | **Best.** No artifacts, full quality |
| Strix Halo | HEVC | No (SDR) | Good. Clean image |
| Strix Halo | HEVC | Yes | **Broken.** Artifacts at any bitrate |
| Navi 31/32 (RX 7000) | HEVC | No (SDR) | Good. Only SFE option for these GPUs |
| Navi 31/32 (RX 7000) | HEVC | Yes | **Broken.** Artifacts at any bitrate |
| Navi 21 (RX 6000) | HEVC | No (SDR) | Good. Only SFE option for these GPUs |

## What this does

The patcher removes the following restrictions from `amfrtdrv64.dll` (AMD's encoder driver):

- **Resolution gate:** removes the 4K minimum (`width * height >= 0x7E9000`) check
- **Heuristic bypass:** removes the check that decides SFE "isn't needed"
- **Device whitelist bypass:** forces the SFE enable flag on all devices
- **SFE disable writes:** NOPs code paths that turn SFE off based on encoder settings

Unlike Vibepollo's NVENC implementation where split encode is a toggle in the UI, this is a **driver-level modification**. There is no on/off switch. Once the DLL is patched, SFE is enabled for every encode session on the system until you restore the original DLL.

## Three tools

### `amf-sfe-patch-dynamic.exe` (Dynamic patcher, recommended)

Works across driver versions by analyzing the DLL structure at runtime instead of relying on hardcoded byte patterns. Parses the PE, finds the SFE setup function via string references, discovers struct offsets dynamically, then patches.

```
amf-sfe-patch-dynamic.exe --analyze            # deep scan and report, no changes
amf-sfe-patch-dynamic.exe --replace            # patch in-place (creates .bak backup)
amf-sfe-patch-dynamic.exe --patch -o out.dll   # patch to a new file
```

Run `--analyze` first to see what it finds before committing to a patch.

### `amf-sfe-patch.exe` (Static file patcher)

Uses exact byte patterns for known driver versions. Faster and simpler, but only works on tested drivers.

```
amf-sfe-patch.exe --verify              # scan only, no changes
amf-sfe-patch.exe --replace             # patch in-place (creates .bak backup)
amf-sfe-patch.exe --patch -o out.dll    # patch to a new file
```

### `amf-sfe-launch.exe` (Runtime memory patcher)

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
4. Check the output. It should find your DLL and list all patch sites.
5. If it looks good: `amf-sfe-patch-dynamic.exe --replace`
6. Restart your streaming server (Sunshine/Apollo/Vibepollo)

To revert, restore the `.bak` file or reinstall your AMD drivers.

## How to verify it's working

After patching and restarting your streaming server, you want to confirm that both VCN instances are actually encoding.

1. **Disable Hardware Accelerated GPU Scheduling (HAGS).** HAGS can make a dual encode session appear as a single one in monitoring tools. Go to Settings > System > Display > Graphics > Change default graphics settings and turn off "Hardware-accelerated GPU scheduling." Reboot after changing this.

2. **Open Task Manager** and go to the Performance tab. Look at your GPU.

3. **Start a streaming session** from your Moonlight client.

4. **Check Video Encode activity.** You should see load on both "Video Codec 0" and "Video Codec 1" (or "Video Encode 0" / "Video Encode 1" depending on your driver version). If only one codec engine shows activity, SFE is not active.

If both engines show encode load, split frame encoding is working. You can re-enable HAGS afterward if you want. The patch still works either way; HAGS just affects how Task Manager reports the activity.

## Compatibility

- **Tested on:** Radeon 8060S (Strix Halo, device ID 0x1586) at 1440p
- See [Supported hardware](#supported-hardware) above for the full GPU compatibility table

## Driver version support

**Dynamic patcher** (`amf-sfe-patch-dynamic.exe`): Should work on any driver version as long as AMD keeps the `HevcMultiHwInstanceEncode` string and the same general function structure. It discovers all offsets at runtime with no hardcoded patterns.

**Static patcher** (`amf-sfe-patch.exe` / `amf-sfe-launch.exe`): Confirmed for:
- **Adrenalin 25.3.1** (latest as of April 2026), `u0198975` driver package
- **Older driver**, `u0420529` driver package

If neither tool works on your driver, run `amf-sfe-patch-dynamic.exe --analyze` and [open an issue](../../issues) with the full output and your driver version.

## How the dynamic patcher works

Instead of hardcoded byte patterns that break across driver updates, the dynamic patcher uses structural analysis:

1. **Parse PE.** Reads the DLL's section headers to find `.text` (code) and data sections.
2. **Find anchor string.** Locates the `"HevcMultiHwInstanceEncode"` UTF-16 wide string in the data section.
3. **Follow cross-references.** Scans `.text` for `LEA` instructions that reference the string's RVA, giving us the SFE setup function.
4. **Discover struct offsets.** Within the setup function, finds `MOV byte [reg+offset], 1` instructions to discover the SFE flag offset (e.g., `0xC2C` in current drivers), and conditional writes to find the whitelist flag offset (e.g., `0x602`).
5. **Patch by structure.** Uses the discovered offsets to find and NOP:
   - Resolution gate: `CMP EAX, 0x7E9000` (4K pixel count constant)
   - Heuristic check: `CMP byte [reg+heuristic_offset], 0 / JZ` with large jump displacement
   - Whitelist conditional: `JNZ`/`JZ` before `MOV byte [reg+whitelist_offset]`
   - SFE disable writes: all `MOV byte [reg+sfe_offset], 0` across the entire `.text` section

This approach is resilient to changes in register allocation, struct layout, and instruction ordering, as long as the logical structure of AMD's encoder init code remains the same.

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

This is a **driver modification** that patches `amfrtdrv64.dll`, a system-wide AMD binary. Use with caution.

The patch only touches the video encoder DLL. It does not affect your display output, GPU compute, or anything outside of hardware video encoding. That said, it is still a driver mod, so:

- **Back up before patching.** The file patcher creates `.bak` backups automatically, but make sure you know where they are.
- **Any application that uses AMD's hardware encoder will be affected.** This includes OBS, Discord, Xbox Game Bar, Teams, and anything else that encodes video through AMF. We can't predict how other software will behave with SFE force-enabled at lower resolutions.
- **Know how to recover.** If something goes wrong:
  1. Rename the `.bak` file back to `amfrtdrv64.dll` (you may need to do this from Safe Mode or a recovery environment if the file is locked)
  2. Or just reinstall your AMD drivers, which will replace the patched DLL with a fresh copy

## License

MIT
