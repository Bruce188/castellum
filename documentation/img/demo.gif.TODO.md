# demo.gif — Capture Procedure

`documentation/img/demo.gif` is currently a **1×1 transparent placeholder** (43 bytes). Replace it with the actual screen-captured GIF using the procedure below.

## What the GIF should show

A ~30-second clip of the full Castellum demo flow:

1. Scan a /24 (POST /api/scan → 202 response visible in terminal)
2. Topology graph populating with discovered devices
3. OT fingerprint result appearing on a selected node (Modbus/TCP)
4. Risk score badge on the CRITICAL device
5. Attack-graph shortest-path rendering in Cytoscape (hop edges with ATT&CK labels)
6. STIX bundle export response in terminal
7. MISP event appearing in MISP UI

## Prerequisites

- Backend: `cd /home/bruce/projects/castellum/backend && ./mvnw spring-boot:run`
- Frontend: `cd /home/bruce/projects/castellum/frontend && npm run dev`
- PostgreSQL 16 running with seed data
- MISP test instance at `MISP_BASE_URL`
- OBS Studio or `ffmpeg -f x11grab` for screen capture

## Capture commands

```bash
# Screen capture via ffmpeg (X11, adjust display/resolution as needed):
ffmpeg -f x11grab -r 30 -s 1280x720 -i :0.0 -codec:v libx264 -preset fast demo.mp4
# Record for ~30 seconds then Ctrl-C

# Or use OBS: File > Settings > Output; record as MP4
```

## Convert to GIF (≤3 MB)

```bash
ffmpeg -i demo.mp4 -vf "fps=12,scale=960:-1:flags=lanczos,palettegen" -y palette.png
ffmpeg -i demo.mp4 -i palette.png \
  -lavfi "fps=12,scale=960:-1:flags=lanczos [x]; [x][1:v] paletteuse" \
  -y demo.gif

# Verify size (must be ≤ 3145728 bytes):
stat -c %s demo.gif
```

If over 3 MB, reduce fps and width:

```bash
ffmpeg -i demo.mp4 -vf "fps=10,scale=720:-1:flags=lanczos,palettegen" -y palette.png
ffmpeg -i demo.mp4 -i palette.png \
  -lavfi "fps=10,scale=720:-1:flags=lanczos [x]; [x][1:v] paletteuse" \
  -y demo.gif
```

## Install

```bash
cp demo.gif /home/bruce/projects/castellum/documentation/img/demo.gif
# Then delete this TODO file once the real GIF is in place:
rm /home/bruce/projects/castellum/documentation/img/demo.gif.TODO.md
```

See `documentation/demo-script.html` §Recording procedure for the full voice-over script.
