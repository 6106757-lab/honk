#!/bin/bash
# 用仓库里的规则源文件刷新 honk 配置里的规则集，然后重载。
#
#   bash ci/update-rules.sh
#
# 规则源文件 config.d/talkatone.dae 是权威副本，网关上的 config.dae 内联了它
# 的内容——规则就写在主配置文件里，一眼能看到，同时又能从仓库更新。
#
# 工作流程：
#   1. 从仓库拉取 config.d/talkatone.dae
#   2. group 段缺 Talkatone 就补上；已有则保留（不覆盖手工调整）
#   3. 用 # >>> talkatone-begin / # <<< talkatone-end 之间的区块替换路由规则
#      区块不存在时，插到 dport(853) -> block 之后（必须早于 geosite 分流，
#      否则 googlesyndication.com 之类会先命中 geosite: google，广告拦不掉）
#   4. honk-core reload
#
# reload 是原子的：候选配置校验不通过时，运行中的实例会记录 rejected 并继续
# 用旧配置，不会把自己断在外面。
set -euo pipefail

REPO=${REPO:-6106757-lab/honk}
CFG=${CONFIG:-/etc/honk/config.dae}
BASE=https://raw.githubusercontent.com/$REPO/main/config.d

[[ -f $CFG ]] || { echo "$CFG not found" >&2; exit 1; }

SRC=$(mktemp)
trap 'rm -f "$SRC"' EXIT
curl -fsSL "$BASE/talkatone.dae" -o "$SRC"
echo "fetched: talkatone.dae ($(wc -l < "$SRC") lines)"

python3 - "$CFG" "$SRC" <<'PY'
import re, sys

cfg, src = sys.argv[1], sys.argv[2]
s = open(cfg, encoding='utf-8').read()
t = open(src, encoding='utf-8').read()


def grab(text, name):
    m = re.search(name + r'\s*\{(.*?)\n\}', text, re.S)
    if not m:
        sys.exit('no %s section in the rule source' % name)
    return m.group(1)


if 'Talkatone {' not in s:
    s = s.replace('group {', 'group {' + grab(t, 'group').rstrip('\n') + '\n', 1)
    print('[ok]   Talkatone 组已加入 group 段')
else:
    print('[skip] Talkatone 组已存在，保留原样')

body = grab(t, 'routing').strip('\n')
block = ('    # >>> talkatone-begin — 由 ci/update-rules.sh 从仓库维护，勿手动编辑\n'
         + body + '\n'
         + '    # <<< talkatone-end')

pat = re.compile(r'[ \t]*# >>> talkatone-begin.*?# <<< talkatone-end', re.S)
if pat.search(s):
    s = pat.sub(block, s, count=1)
    print('[ok]   Talkatone 路由区块已更新')
else:
    anchor = '    dport(853) -> block\n'
    if anchor in s:
        s = s.replace(anchor, anchor + '\n' + block + '\n', 1)
        print('[ok]   Talkatone 路由区块已插入')
    else:
        sys.exit('cannot find the insertion anchor (dport(853) -> block)')

open(cfg, 'w', encoding='utf-8').write(s)
PY

honk-core reload
