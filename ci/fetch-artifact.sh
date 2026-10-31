#!/bin/bash
# Fetch the Build artifact and unpack the binary from it.
#
#   GITHUB_TOKEN=<token with actions:read> bash ci/fetch-artifact.sh [run_id] [outdir]
#
# With no run_id it takes the most recent *successful* Build run, so a bare
# invocation lands on whatever main is currently on. The workflow uploads under
# a fixed artifact name, so this needs no per-commit bookkeeping, and it works
# straight from the gateway: no local build machine in the download path.
set -euo pipefail

REPO=${REPO:-6106757-lab/honk}
TOKEN=${GITHUB_TOKEN:?GITHUB_TOKEN is required (needs actions:read)}
OUT=${2:-./honk-build}
API=https://api.github.com/repos/$REPO
PY=$(command -v python3 || command -v python) || { echo "python is required" >&2; exit 1; }

auth() { curl -sS -H "Authorization: token $TOKEN" -H "Accept: application/vnd.github+json" "$@"; }

run=${1:-}
if [[ -z $run ]]; then
  run=$(auth "$API/actions/workflows/build.yml/runs?status=success&per_page=1" |
    "$PY" -c 'import json,sys
d=json.load(sys.stdin)
runs=d.get("workflow_runs",[])
print(runs[0]["id"] if runs else "")')
fi
[[ -n $run ]] || { echo "no successful Build run; pass a run id or push to main first" >&2; exit 1; }

auth "$API/actions/runs/$run" | "$PY" -c 'import json,sys
d=json.load(sys.stdin)
print("run      :", d["id"])
print("commit   :", d["head_sha"][:8], d.get("display_title", ""))'

url=$(auth "$API/actions/runs/$run/artifacts" |
  "$PY" -c 'import json,sys
d=json.load(sys.stdin)
for a in d.get("artifacts", []):
    if a["name"] == "honk-core-x86_64-unknown-linux-musl-full" and not a["expired"]:
        print(a["archive_download_url"]); break')
[[ -n $url ]] || { echo "artifact missing: the run may still be building, or it expired" >&2; exit 1; }

mkdir -p "$OUT"
auth -L "$url" -o "$OUT/artifact.zip"
(
  cd "$OUT"
  unzip -oq artifact.zip
  rm -f artifact.zip
  found=0
  for t in *.tar.gz; do
    [[ -f $t ]] || continue
    tar -xzf "$t"
    rm -f "$t"
    found=1
  done
  [[ $found == 1 ]] || { echo "no tarball in the artifact" >&2; exit 1; }
)

bin=$(find "$OUT" -type f -name honk-core | head -1)
[[ -n $bin ]] || { echo "no honk-core inside the archive" >&2; exit 1; }
chmod +x "$bin"
echo "binary   : $bin"
ls -l "$bin"
sha256sum "$bin"
"$bin" --version 2>&1 | head -1
