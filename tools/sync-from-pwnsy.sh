#!/usr/bin/env sh
# Refresh the vendored engine files from a pwnsy checkout, then show what changed in the
# pwnsy SOC desk since the commit this repository was last synced from.
#   tools/sync-from-pwnsy.sh ~/2-projects/pwnsy
# The desk itself (engine.js, app.js, data.js) was restructured for this repository, so
# changes there are listed for porting by hand rather than copied.
set -eu
SRC="${1:?usage: tools/sync-from-pwnsy.sh <pwnsy checkout>}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
V="$HERE/app/vendor"
LAST="$(sed -n 's/.*pwnsy commit \([0-9a-f]\{7,\}\).*/\1/p' "$V/README.md" | head -n 1)"
NOW="$(git -C "$SRC" rev-parse --short HEAD)"
DATE="$(git -C "$SRC" log -1 --format=%cs)"

cp "$SRC/tools/detect/sigma.js" "$V/sigma.js"
cp "$SRC/tools/detect/js-yaml.min.js" "$V/js-yaml.min.js"
cp "$SRC/tools/lib/intel.js" "$V/intel.js"
cp "$SRC/tools/detect/data/attack.json" "$V/attack.json"
sed -i.bak "s/pwnsy commit [0-9a-f]\{7,\} ([0-9-]*)/pwnsy commit $NOW ($DATE)/g" "$V/README.md" && rm -f "$V/README.md.bak"

echo "Vendored files now match pwnsy $NOW ($DATE)."
git -C "$HERE" status --short -- app/vendor
if [ -n "$LAST" ] && [ "$LAST" != "$NOW" ]; then
  echo
  echo "SOC desk changes in pwnsy since $LAST, to port by hand:"
  git -C "$SRC" log --oneline "$LAST..HEAD" -- tools/detect/soc-desk tools/detect/sigma.js tools/lib/intel.js
  echo
  echo "Diff: git -C \"$SRC\" diff $LAST..HEAD -- tools/detect/soc-desk"
fi
echo
echo "Then run: npm test"
