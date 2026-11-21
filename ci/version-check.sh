#!/bin/bash
# 태그가 버전 정책을 따르는가(docs/개발-안내.md "버전 번호") — 배포 워크플로가 태그를 받으면 부른다.
#
#   bash ci/version-check.sh <태그> [--ref <커밋 · 태그>]
#
# 태그는 둘 중 하나다(시험판은 둘 다 꼬리 `-rc.<N>`):
#   v<엔진 버전>       엔진(실행 파일)이 바뀐 출시 — 엔진 버전은 Cargo.toml 의 SemVer
#   rules-<룰 버전>    룰만 바뀐 출시 — 룰 버전은 plugins/RULES-VERSION 의 날짜(YYYY.MM.DD · 같은 날 둘째부터 꼬리 .N)
#
# 견주는 것은 지난 정식 공개본 — `--ref`(기본 HEAD)의 첫 부모 역사에서 가장 가까운 정식 태그(시험판과 이 태그는 빼고)다.
#   v 태그      태그 = Cargo.toml 의 버전 · 엔진이 바뀌었다 · 엔진 버전이 더 높다
#   rules 태그  태그 = plugins/RULES-VERSION · 엔진이 그대로다(엔진 버전 문자열도) · 룰이 바뀌었다
#   둘 다       룰이 바뀌었으면 룰 버전이 더 높고, 그대로면 룰 버전도 그대로다
# rules 태그의 출시는 지난 공개본의 실행 파일을 그대로 싣는다(.github/workflows/release.yml) — 그 공개본이 여기서 견준
# 태그다. 잡 안에서 돌면(`GITHUB_OUTPUT`) 그 태그를 `prev=<태그>` 로 낸다.
# '엔진' 은 실행 파일을 짓는 것 전부다 — crates/ · Cargo.toml · Cargo.lock · rust-toolchain.toml · .cargo/config.toml
# (Cargo.toml · Cargo.lock 의 엔진 버전 문자열은 가리고 견준다 — 버전만 올린 것은 엔진이 바뀐 것이 아니다).
# '룰' 은 plugins/ 전부다(룰 버전 파일은 빼고). 지난 공개본이 없으면 견줄 것이 없어 꼴만 본다.
# 태그와 그 역사가 있어야 한다 — 워크플로는 `fetch-depth: 0` 으로 받는다.
set -euo pipefail

TAG=""
REF=HEAD
while [ $# -gt 0 ]; do
    case "$1" in
        --ref) REF=$2; shift 2 ;;
        -*) echo "모르는 인자: $1" >&2; exit 2 ;;
        *) [ -z "$TAG" ] || { echo "태그는 하나만: $1" >&2; exit 2; }; TAG=$1; shift ;;
    esac
done
[ -n "$TAG" ] || { echo "쓰는 법: bash ci/version-check.sh <태그> [--ref <커밋>]" >&2; exit 2; }

fail() { echo "::error::$*"; exit 1; }

RULES_RE='[0-9]{4}\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])(\.([2-9]|[1-9][0-9]+))?'
ENGINE_RE='[0-9]+\.[0-9]+\.[0-9]+'

# 다 받은 뒤 고른다 — `git show | grep -m1` 은 grep 이 먼저 닫으면 git 이 SIGPIPE 로 끝나 pipefail 에 걸린다.
engine_at() { local t; t=$(git show "$1:Cargo.toml"); grep -m1 -E '^\s*version' <<<"$t" | cut -d'"' -f2; }
rules_at() { git show "$1:plugins/RULES-VERSION" 2>/dev/null | tr -d '\r\n' || true; }
# b 가 a 보다 높은가 — 둘 다 점으로 가른 수다(엔진은 X.Y.Z · 룰은 날짜).
higher() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$2" ]; }

# 엔진을 짓는 것 — 엔진 버전을 가린 꼴로 늘어놓는다. 두 커밋의 이것이 같으면 엔진이 그대로다. 가리는 것은 그 버전이 적힌
# 자리뿐이다 — Cargo.toml 의 [workspace.package] 와 Cargo.lock 에서 출처(`source`)가 없는 패키지(작업 공간 크레이트).
# 버전 문자열을 통째로 바꾸면 그 버전과 우연히 같은 외부 의존성까지 한쪽에서만 가려진다(1.20.1 이 그랬다).
ENGINE_PATHS=(crates Cargo.toml Cargo.lock rust-toolchain.toml .cargo/config.toml)
mask_toml() { awk '/^\[/ { sec = $0 } sec == "[workspace.package]" && /^version *= *"/ { print "version = \"<V>\""; next } { print }'; }
mask_lock() {
    awk 'function flush(  i, l) { for (i = 1; i <= n; i++) { l = buf[i]; if (!src && l ~ /^version = "/) l = "version = \"<V>\""; print l }; n = 0; src = 0 }
         /^\[\[package\]\]$/ { flush() }
         /^source = / { src = 1 }
         { buf[++n] = $0 }
         END { flush() }'
}
engine_tree() {
    local ref=$1
    git ls-tree -r "$ref" -- "${ENGINE_PATHS[@]}" | grep -v -E $'\t(Cargo\\.toml|Cargo\\.lock)$'
    echo "== Cargo.toml"
    { git show "$ref:Cargo.toml" 2>/dev/null || true; } | mask_toml
    echo "== Cargo.lock"
    { git show "$ref:Cargo.lock" 2>/dev/null || true; } | mask_lock
}
engine_same() { cmp -s <(engine_tree "$1") <(engine_tree "$2"); }
rules_same() { git diff --quiet "$1" "$2" -- plugins/ ':!plugins/RULES-VERSION'; }

ENGINE=$(engine_at "$REF")
[[ "$ENGINE" =~ ^$ENGINE_RE$ ]] || fail "엔진 버전을 읽지 못했다: '$ENGINE'"
RULES=$(rules_at "$REF")
[[ "$RULES" =~ ^$RULES_RE$ ]] || fail "plugins/RULES-VERSION 이 없거나 꼴이 틀렸다: '$RULES' — YYYY.MM.DD(같은 날 둘째부터 .2)"

if [[ "$TAG" =~ ^v($ENGINE_RE)(-rc\.[0-9]+)?$ ]]; then
    KIND=engine
    [ "${BASH_REMATCH[1]}" = "$ENGINE" ] || fail "태그 $TAG 가 엔진 버전 v$ENGINE(시험판은 v$ENGINE-rc.<N>)과 다르다"
elif [[ "$TAG" =~ ^rules-($RULES_RE)(-rc\.[0-9]+)?$ ]]; then
    KIND=rules
    [ "${BASH_REMATCH[1]}" = "$RULES" ] || fail "태그 $TAG 가 룰 버전 rules-$RULES(시험판은 rules-$RULES-rc.<N>)과 다르다"
else
    fail "태그 $TAG 는 v<엔진 버전> 도 rules-<룰 버전> 도 아니다"
fi

# 태그가 이미 있으면 이 커밋을 가리켜야 한다 — 다시 돌릴 때(워크플로 재실행 · 시험판 커밋에 민 정식 태그)는 그렇고, 다른 커밋의
# 같은 이름은 지난 공개본을 그 태그 앞에서 찾게 해 엉뚱한 것과 견준다.
if have=$(git rev-parse -q --verify "refs/tags/$TAG^{commit}"); then
    [ "$have" = "$(git rev-parse "$REF^{commit}")" ] || fail "태그 $TAG 는 이미 다른 커밋(${have:0:12})에 있다"
fi
# 사선이 든 이름은 빼고 고른 뒤 꼴을 다시 잰다 — `--match` 의 `*` 는 `/` 를 넘어 `v0/x` 같은 이름도 고르는데, 태그 룰셋
# (`refs/tags/v*` · `refs/tags/rules-*`)의 `*` 는 `/` 를 넘지 않아 그런 이름은 조직 Owner 가 아니어도 만든다. 룰만 바뀐
# 출시는 고른 태그의 Release 에서 실행 파일을 받아 싣는다 — Owner 만 만드는 정식 태그만 그 출처가 된다.
PREV=$(git describe --tags --abbrev=0 --first-parent --match 'v[0-9]*' --match 'rules-[0-9]*' \
    --exclude '*-rc.*' --exclude '*/*' --exclude "$TAG" "$REF" 2>/dev/null || true)
if [ -z "$PREV" ]; then
    echo "지난 정식 공개본이 없다 — 꼴만 봤다($TAG · 엔진 $ENGINE · 룰 $RULES)"
    exit 0
fi
[[ "$PREV" =~ ^(v$ENGINE_RE|rules-$RULES_RE)$ ]] || fail "지난 공개본으로 고른 태그 $PREV 가 정식 태그(v<엔진 버전> · rules-<룰 버전>)의 꼴이 아니다"
PREV_ENGINE=$(engine_at "$PREV")
PREV_RULES=$(rules_at "$PREV")

if engine_same "$PREV" "$REF"; then engine_changed=0; else engine_changed=1; fi
if rules_same "$PREV" "$REF"; then rules_changed=0; else rules_changed=1; fi

if [ "$KIND" = engine ]; then
    [ "$engine_changed" = 1 ] || fail "엔진이 $PREV 와 같다 — 룰만 바뀌었으면 rules-$RULES 로 낸다"
    higher "$PREV_ENGINE" "$ENGINE" || fail "엔진 버전 $ENGINE 이 지난 공개본($PREV)의 $PREV_ENGINE 보다 높지 않다"
else
    [ "$engine_changed" = 0 ] || fail "엔진이 $PREV 와 다르다 — 엔진이 바뀐 출시는 엔진 버전을 올려 v<버전> 으로 낸다"
    [ "$rules_changed" = 1 ] || fail "룰이 $PREV 와 같다 — 낼 것이 없다"
    # 엔진 나무는 버전 줄을 가리고 견준다 — 버전 문자열만 올린 커밋은 위를 지난다. 그대로 내면 지난 공개본의 실행 파일
    # (옛 버전)에 새 버전의 README · 제목이 붙는다.
    [ "$ENGINE" = "$PREV_ENGINE" ] || fail "엔진 버전이 지난 공개본($PREV)의 $PREV_ENGINE 에서 $ENGINE 으로 바뀌었다 — 룰만 바뀐 출시는 그 공개본의 실행 파일을 그대로 싣는다. 버전을 되돌리거나, 엔진을 고쳐 v$ENGINE 으로 낸다"
fi
if [ -n "$PREV_RULES" ]; then
    if [ "$rules_changed" = 1 ]; then
        higher "$PREV_RULES" "$RULES" || fail "룰이 바뀌었는데 룰 버전 $RULES 이 지난 공개본($PREV)의 $PREV_RULES 보다 높지 않다"
    else
        [ "$RULES" = "$PREV_RULES" ] || fail "룰이 $PREV 와 같은데 룰 버전을 $PREV_RULES → $RULES 로 바꿨다"
    fi
fi
# 배포 워크플로가 지난 공개본을 받아 쓴다 — 사람이 읽는 아래 줄을 파싱하지 않게 따로 낸다.
[ -z "${GITHUB_OUTPUT:-}" ] || echo "prev=$PREV" >>"$GITHUB_OUTPUT"
echo "버전 OK — $TAG · 지난 공개본 $PREV · 엔진 $PREV_ENGINE → $ENGINE · 룰 ${PREV_RULES:-없음} → $RULES"
