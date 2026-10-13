"""Build the static GitHub Pages demo (docs/demo/) from the real dashboard HTML.

    python tools/demo/build_pages.py

Writes docs/demo/index.html (dashboard + demo player), player.js, sample.json and
static/flasher.js. Serve docs/ with GitHub Pages (Settings > Pages > branch main, /docs)
or locally: python -m http.server -d docs 8099  ->  http://127.0.0.1:8099/demo/
"""
import os, shutil, sys, tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, ROOT)
os.environ.setdefault("SNIFF_CAPTURES", os.path.join(tempfile.gettempdir(), "sniff_sight_pages"))
os.environ["SNIFF_NO_SERIAL"] = "1"
from sniff_sight import web  # noqa: E402

out = os.path.join(ROOT, "docs", "demo")
os.makedirs(os.path.join(out, "static"), exist_ok=True)
tags = '<script>window.SS_DEMO_SAMPLE = "sample.json";</script>\n  <script src="player.js"></script>\n  '
html = web.demo_html(tags).replace('src="/static/flasher.js"', 'src="static/flasher.js"')
html = html.replace("<title>", '<meta name="robots" content="noindex">\n  <title>', 1)
with open(os.path.join(out, "index.html"), "w", encoding="utf-8", newline="\n") as fh:
    fh.write(html)
pkg = os.path.join(ROOT, "sniff_sight")
shutil.copyfile(os.path.join(pkg, "demo", "player.js"), os.path.join(out, "player.js"))
shutil.copyfile(os.path.join(pkg, "demo", "sample.json"), os.path.join(out, "sample.json"))
shutil.copyfile(os.path.join(pkg, "static", "flasher.js"), os.path.join(out, "static", "flasher.js"))
print("wrote", out)