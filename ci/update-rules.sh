#!/bin/bash
# 从仓库重新拉取 config.d 下的规则文件并重载 honk。
#
#   bash ci/update-rules.sh
#
# 规则文件的权威副本在仓库里，网关上只是缓存。改动推到 main 之后跑这个脚本，
# 就能把新规则拉下来生效。reload 是原子的：新配置校验失败时运行中的实例会
# 记录 rejected 并继续用旧配置，不会把自己断在外面。
set -euo pipefail

REPO=${REPO:-6106757-lab/honk}
DIR=${RULES_DIR:-/etc/honk/config.d}
BASE=https://raw.githubusercontent.com/$REPO/main/config.d

[[ -d $DIR ]] || { echo "$DIR does not exist; run the deploy step first" >&2; exit 1; }

cd "$DIR"
for f in *.dae; do
    [[ -f $f ]] || continue
    before=$(sha256sum "$f" | cut -d' ' -f1)
    curl -fsSL "$BASE/$f" -o "$f"
    after=$(sha256sum "$f" | cut -d' ' -f1)
    if [[ $before == "$after" ]]; then
        echo "unchanged: $f"
    else
        echo "updated:   $f"
    fi
done

honk-core reload
