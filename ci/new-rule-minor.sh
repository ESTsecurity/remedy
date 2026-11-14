#!/bin/bash
# 새 룰은 마이너를 올린다(docs/개발-안내.md "판 번호") — 배포 워크플로가 태그를 받으면 부른다.
#
#   bash ci/new-rule-minor.sh [--ref <커밋 · 태그>] [--version <버전>]
#
# 지난 정식 공개본(이 버전보다 낮은 가장 높은 `vX.Y.Z` 태그 — 시험판 꼬리 `-rc.N` 은 빼고)의 `plugins/` 에 없던 룰
# 폴더가 `--ref`(기본 HEAD)에 있는데 메이저 · 마이너가 지난 공개본과 같으면 — 패치만 올렸으면 — 종료 1 이다.
# 지난 공개본이 없으면 견줄 것이 없어 0. `--version` 은 시험용이다(주지 않으면 `--ref` 의 Cargo.toml 에서 읽는다).
# 태그와 그 역사가 있어야 한다 — 워크플로는 `fetch-depth: 0` 으로 받는다.
set -euo pipefail

REF=HEAD
VERSION=""
while [ $# -gt 0 ]; do
    case "$1" in
        --ref) REF=$2; shift 2 ;;
        --version) VERSION=$2; shift 2 ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done
[ -n "$VERSION" ] || VERSION=$(git show "$REF:Cargo.toml" | grep -m1 -E '^\s*version' | cut -d'"' -f2)
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "버전을 읽지 못했다: '$VERSION'" >&2; exit 2; }

# 정식 태그와 이 버전을 함께 판 순서로 늘어놓아 바로 앞의 것을 고른다 — 이 버전의 태그가 이미 있어도(정식 태그를 민
# 뒤) 그 앞이 지난 공개본이다.
prev=$( {
    git tag --list 'v*' | sed -n 's/^v\([0-9]*\.[0-9]*\.[0-9]*\)$/\1/p'
    echo "$VERSION"
} | sort -V | grep -B1 -x -F "$VERSION" | head -1)
if [ "$prev" = "$VERSION" ]; then
    echo "지난 정식 공개본이 없다 — 견줄 것이 없다(v$VERSION)"
    exit 0
fi

new=$(comm -13 <(git ls-tree -d --name-only "v$prev" plugins/ | sort) <(git ls-tree -d --name-only "$REF" plugins/ | sort))
count=$(printf '%s\n' "$new" | grep -c . || true)
names=$(printf '%s\n' "$new" | sed 's#^plugins/##' | tr '\n' ' ' | sed 's/ $//')
if [ "$count" -gt 0 ] && [ "${VERSION%.*}" = "${prev%.*}" ]; then
    echo "::error::새 룰 ${count}개(${names})가 있는데 v$prev → v$VERSION 은 패치다 — 새 룰은 마이너를 올린다(docs/개발-안내.md 판 번호)"
    exit 1
fi
echo "판 번호 OK — v$prev → v$VERSION · 새 룰 ${count}개${names:+ ($names)}"
