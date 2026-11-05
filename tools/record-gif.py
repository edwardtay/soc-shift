#!/usr/bin/env python3
"""Record the README walkthrough GIF with Playwright (headless Chromium, 1280x720).

Serve the app first, then run this script:
  python3 -m http.server 8850 --directory app &
  python3 tools/record-gif.py http://127.0.0.1:8850/ docs/media/soc-shift.gif

Needs: pip install playwright && playwright install chromium, and ffmpeg on PATH.
The OSV lookup is live, so the machine needs network access.

Frames are lossless screenshots held for a set time (no screen video), so
unchanged screens cost almost nothing in the GIF.
"""
import os, subprocess, sys, tempfile
from playwright.sync_api import sync_playwright

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8850/"
out = sys.argv[2] if len(sys.argv) > 2 else "docs/media/soc-shift.gif"
W, H, OUT_W = 1280, 720, 960
tmp = tempfile.mkdtemp(prefix="soc-shift-gif-")
frames = []

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": W, "height": H})
    pg = ctx.new_page()

    def snap(hold_ms):
        pg.wait_for_timeout(150)
        f = os.path.join(tmp, "f%03d.png" % len(frames))
        pg.screenshot(path=f)
        frames.append((f, hold_ms / 1000))

    def type_in(sel, text, steps=4, hold=250):
        pg.fill(sel, "")
        n = len(text)
        for i in range(1, steps + 1):
            pg.fill(sel, text[: round(n * i / steps)])
            snap(hold)

    pg.goto(url)
    pg.evaluate("localStorage.clear()")
    pg.reload()
    pg.wait_for_selector("#ack")
    pg.evaluate("window.scrollTo(0, document.getElementById('desk').getBoundingClientRect().top + window.scrollY)")
    snap(1500)
    # 1. take the handover
    pg.click("#ack"); snap(1600)
    # 2. move the clock and open the take-home alert
    pg.click("[data-adv='60']"); snap(600)
    pg.click("[data-adv='60']"); snap(900)
    pg.click("#tabs [data-tab=queue]"); snap(700)
    pg.click("[data-sel='R-EDR-001|KL-MBP-0142']"); snap(1700)
    # 3. verdict with a reason
    pg.locator("#vform").scroll_into_view_if_needed()
    pg.click("[data-v=tp]"); snap(700)
    type_in("#vreason", "node spawned curl to 203.0.113.47:1224 right after npm install of a take-home repo.")
    pg.click("#vsave"); snap(1500)
    # 4. pivot: host timeline, then the npm package, then live lookups (OSV returns MAL-2024-8847)
    pg.click("[data-sel='R-EDR-001|KL-MBP-0142']")
    host = pg.locator("#main button.ent[data-ent='host|KL-MBP-0142']").first
    host.scroll_into_view_if_needed(); snap(900)
    host.click(); snap(1300)
    pkg = pg.locator("#drawer button.ent[data-ent='package|ethersscan-api']").first
    pkg.scroll_into_view_if_needed(); snap(1300)
    pkg.click(); snap(900)
    pg.click("#drun")
    pg.wait_for_selector("#denrich .live", timeout=30000)
    pg.locator("#denrich").scroll_into_view_if_needed(); snap(3400)
    pg.click("#dclose")
    # 5. jump to the end of the shift and close the scanner alert as a false positive
    pg.click("[data-adv='end']"); snap(900)
    pg.click("[data-sel='R-WAF-001|10.20.0.15']"); snap(1300)
    pg.locator("#vform").scroll_into_view_if_needed()
    pg.click("[data-v=fp]")
    type_in("#vreason", "Approved scanner CHG-2291 inside its window, staging host only.", steps=3)
    pg.click("#vsave"); snap(900)
    # 6. tuning with the regression check
    pg.click("#tabs [data-tab=tune]"); snap(1200)
    pg.click("[data-tune='R-WAF-001']")
    pg.locator(".diff").scroll_into_view_if_needed(); snap(3200)
    # 7. incident observables with IOC, TLP and PAP, ready to export
    pg.wait_for_timeout(2700)  # let the last toast clear
    pg.click("#tabs [data-tab=inc]")
    pg.locator("table.obs").first.evaluate("e => e.scrollIntoView({block: 'center'})"); snap(2600)
    # 8. handover check, then shift timing
    pg.click("#tabs [data-tab=out]"); snap(3000)
    pg.locator(".counters.mt").evaluate("e => e.scrollIntoView({block: 'center'})"); snap(3000)
    ctx.close(); b.close()

lst = os.path.join(tmp, "frames.txt")
with open(lst, "w") as fh:
    for f, d in frames:
        fh.write("file '%s'\nduration %.3f\n" % (f, d))
    fh.write("file '%s'\n" % frames[-1][0])
palette = os.path.join(tmp, "palette.png")
vf = "scale=%d:-1:flags=lanczos" % OUT_W
subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", lst, "-vf", vf + ",palettegen=max_colors=128:stats_mode=full", palette], check=True)
subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", lst, "-i", palette,
                "-lavfi", vf + " [x]; [x][1:v] paletteuse=dither=none:diff_mode=rectangle", "-vsync", "vfr", out], check=True)
total = sum(d for _, d in frames)
print(out, "%.2f MB" % (os.path.getsize(out) / 1e6), "%d frames" % len(frames), "%.1f s" % total)
