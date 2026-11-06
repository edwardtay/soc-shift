#!/usr/bin/env python3
"""Render docs/media/social-preview.png (1280x640) with Playwright.

Serve the app first, then run this script:
  python3 -m http.server 8850 --directory app &
  python3 tools/social-preview.py http://127.0.0.1:8850/ docs/media/social-preview.png

Takes a real screenshot of the Kestrel Ledger alert queue with the entity drawer open on the npm package
after a live OSV lookup (MAL-2024-8847), then lays it beside the title on a 1280x640 card.
Needs: pip install playwright && playwright install chromium, and network access for the OSV lookup.
GitHub has no API for the social preview: upload the PNG under Settings, General, Social preview.
"""
import base64, os, shutil, sys, tempfile
from playwright.sync_api import sync_playwright

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8850/"
out = sys.argv[2] if len(sys.argv) > 2 else "docs/media/social-preview.png"
tmp = tempfile.mkdtemp(prefix="soc-shift-preview-")
shot = os.path.join(tmp, "desk.png")

CARD = """<!doctype html><html lang="en"><head><meta charset="utf-8"><style>
:root { --ink: #0f172a; --muted: #475569; --line: #94a3b8; --accent: #047857; --bg: #f1f5f9; }
* { box-sizing: border-box; margin: 0; }
body { width: 1280px; height: 640px; background: var(--bg); color: var(--ink); font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; padding: 34px 40px 0; overflow: hidden; }
header { display: flex; align-items: center; gap: 22px; height: 96px; }
.mark { display: flex; align-items: center; gap: 14px; flex: none; }
h1 { font-size: 54px; line-height: 1; letter-spacing: -1px; white-space: nowrap; }
p { font-size: 23px; line-height: 1.35; color: var(--muted); border-left: 2px solid var(--line); padding-left: 22px; }
p b { color: var(--accent); font-weight: 650; }
.frame { margin-top: 20px; height: 500px; border: 2px solid var(--line); border-bottom: 0; border-radius: 12px 12px 0 0; overflow: hidden; background: #fff; }
.frame img { display: block; width: 1196px; }
</style></head><body>
<header>
  <div class="mark"><svg viewBox="0 0 32 32" width="54" height="54" aria-hidden="true"><rect width="32" height="32" rx="7" fill="#047857"/><circle cx="16" cy="16" r="9" fill="none" stroke="#fff" stroke-width="2.5"/><path d="M16 9.5V16l4.5 3" stroke="#fff" stroke-width="2.5" fill="none" stroke-linecap="round"/></svg><h1>SOC Shift</h1></div>
  <p>Work a full SOC analyst shift in your browser: triage, pivot, respond, hunt, tune and hand over. <b>Open source, MIT.</b></p>
</header>
<div class="frame"><img src="data:image/png;base64,%s" alt=""></div>
</body></html>"""

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context(viewport={"width": 1196, "height": 760})
    pg = ctx.new_page()
    pg.goto(url + "?scenario=kestrel-ledger")
    pg.evaluate("localStorage.clear()")
    pg.reload()
    pg.wait_for_selector("#ack")
    pg.click("#ack")
    pg.click("[data-adv='60']"); pg.click("[data-adv='60']")
    pg.click("#tabs [data-tab=queue]")
    pg.click("[data-sel='R-EDR-001|KL-MBP-0142']")
    pg.evaluate("window.scrollTo(0, document.getElementById('desk').getBoundingClientRect().top + window.scrollY)")
    pg.locator("#main button.ent[data-ent='host|KL-MBP-0142']").first.click()
    pg.locator("#drawer button.ent[data-ent='package|ethersscan-api']").first.click()
    pg.click("#drun")
    pg.wait_for_selector("#denrich .live", timeout=30000)
    pg.wait_for_function("document.getElementById('denrich').textContent.includes('MAL-2024-8847')", timeout=30000)
    pg.wait_for_timeout(400)
    pg.screenshot(path=shot)
    card = ctx.new_page()
    card.set_viewport_size({"width": 1280, "height": 640})
    with open(shot, "rb") as fh:
        card.set_content(CARD % base64.b64encode(fh.read()).decode())
    card.wait_for_timeout(200)
    card.screenshot(path=out)
    ctx.close(); b.close()
shutil.rmtree(tmp, ignore_errors=True)
print(out, "%.0f KB" % (os.path.getsize(out) / 1024))
