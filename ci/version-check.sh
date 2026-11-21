#!/bin/bash
# 태그가 버전 정책을 따르는가(docs/개발-안내.md "버전 번호") — 배포 워크플로가 태그를 받으면 부른다. 태그를 밀기 전에
# `ci/batch.sh` 도 부른다.
#
#   bash ci/version-check.sh <태그> [--ref <커밋>] [--prev <태그> --prev-name '<Release 이름>'] [--rules <룰 버전>]
#                            [--today YYYY-MM-DD] [--no-prev]
#
# 태그는 둘 중 하나다(시험판은 둘 다 꼬리 `-rc.<N>`):
#   v<엔진 버전>       엔진(실행 파일)이 바뀐 출시 — 엔진 버전은 Cargo.toml 의 SemVer. 룰 버전은 주석 태그 메시지의 첫 줄
#                      '프로그램 <엔진 버전> · 룰 <룰 버전>' 에 적는다(`bash ci/batch.sh engine-tag <태그>` 가 짓는다 ·
#                      태그를 만들기 전에 부를 때는 `--rules`)
#   rules-<룰 버전>    룰만 바뀐 출시 — 룰 버전(YYYY.MM.DD · 같은 날 둘째부터 꼬리 .N)이 태그 이름이다
#
# 견주는 것은 **지금 Latest**(공개된 정식 Release · 2026-11-21 부터)다 — `--prev` 와 그 Release 의 이름 `--prev-name`
# ('프로그램 <엔진> · 룰 <룰>')을 주거나, 주지 않으면 gh 로 읽는다(GH_TOKEN 이나 gh 로그인). 룰만 바뀐 출시는 그 Release
# 의 실행 파일을 그대로 싣는다(.github/workflows/release.yml). 전에는 첫 부모 역사에서 가장 가까운 태그를 골랐다 — 병합으로
# 들어온 태그를 건너뛰었고, main 에 공개 전 엔진 변경이 있으면 룰 출시가 멈췄다(목표 remedy_하루30건_대응체계 차례 2).
#   둘 다       Latest 가 이 커밋의 조상이다(아니면 새 출시가 Latest 의 룰을 빠뜨린다) · 룰이 바뀌었으면 룰 버전이 Latest
#               보다 높고, 그대로면 룰 버전도 그대로다 · 룰 버전의 날이 오늘(KST)+1 을 넘지 않는다
#   v 태그      태그 = Cargo.toml 의 버전 · 엔진이 Latest 가 싣는 엔진(태그 v<그 버전>)과 다르다 · 엔진 버전이 더 높다
#   rules 태그  룰이 바뀌었다 — main 의 엔진이 공개본보다 앞서 있어도 된다. 싣는 엔진은 Latest 의 것이고, 배포 잡이 그
#               실행 파일로 모든 룰을 lint 한다(공개본 엔진이 읽지 못하는 룰은 거기서 멈춘다)
# 잡 안에서 돌면(`GITHUB_OUTPUT`) `prev=` · `prev_engine=` · `engine=`(이 출시가 싣는 엔진) · `rules=` 를 낸다.
# '엔진' 은 실행 파일을 짓는 것 전부다 — crates/ · Cargo.toml · Cargo.lock · rust-toolchain.toml · .cargo/config.toml
# (Cargo.toml · Cargo.lock 의 엔진 버전 문자열은 가리고 견준다 — 버전만 올린 것은 엔진이 바뀐 것이 아니다).
# '룰' 은 plugins/ 전부다 — 옛 룰 버전 파일 · 잠금 · 룰 폴더의 개발 키 서명(MANIFEST · MANIFEST.minisig)은 빼고.
# 태그와 그 역사가 있어야 한다 — 워크플로는 `fetch-depth: 0` 으로 받는다. `--no-prev` 는 꼴만 본다(시험 · 첫 출시).
set -euo pipefail

TAG="" REF=HEAD PREV="" PREV_NAME="" RULES_ARG="" TODAY="" NO_PREV=0
while [ $# -gt 0 ]; do
    case "$1" in
        --ref) REF=$2; shift 2 ;;
        --prev) PREV=$2; shift 2 ;;
        --prev-name) PREV_NAME=$2; shift 2 ;;
        --rules) RULES_ARG=$2; shift 2 ;;
        --today) TODAY=$2; shift 2 ;;
        --no-prev) NO_PREV=1; shift ;;
        -*) echo "모르는 인자: $1" >&2; exit 2 ;;
        *) [ -z "$TAG" ] || { echo "태그는 하나만: $1" >&2; exit 2; }; TAG=$1; shift ;;
    esac
done
[ -n "$TAG" ] || { echo "쓰는 법: bash ci/version-check.sh <태그> [--ref <커밋>] [--prev <태그> --prev-name <이름>] [--rules <룰 버전>]" >&2; exit 2; }

fail() { echo "::error::$*"; exit 1; }

RULES_RE='[0-9]{4}\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])(\.([2-9]|[1-9][0-9]+))?'
ENGINE_RE='[0-9]+\.[0-9]+\.[0-9]+'

# 다 받은 뒤 고른다 — `git show | grep -m1` 은 grep 이 먼저 닫으면 git 이 SIGPIPE 로 끝나 pipefail 에 걸린다.
engine_at() { local t; t=$(git show "$1:Cargo.toml"); grep -m1 -E '^\s*version' <<<"$t" | cut -d'"' -f2; }
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
rules_same() {
    git diff --quiet "$1" "$2" -- plugins/ ':!plugins/RULES-VERSION' ':!plugins/versions.lock.json' \
        ':!plugins/*/MANIFEST' ':!plugins/*/MANIFEST.minisig'
}
# Release 이름 '프로그램 <엔진> · 룰 <룰>' → 두 값(꼴이 아니면 빈 값).
name_engine() { sed -nE "s/^프로그램 ($ENGINE_RE) · 룰 ($RULES_RE)\$/\\1/p" <<<"$1"; }
name_rules() { sed -nE "s/^프로그램 ($ENGINE_RE) · 룰 ($RULES_RE)\$/\\2/p" <<<"$1"; }

ENGINE=$(engine_at "$REF")
[[ "$ENGINE" =~ ^$ENGINE_RE$ ]] || fail "엔진 버전을 읽지 못했다: '$ENGINE'"

if [[ "$TAG" =~ ^v($ENGINE_RE)(-rc\.[0-9]+)?$ ]]; then
    KIND=engine
    [ "${BASH_REMATCH[1]}" = "$ENGINE" ] || fail "태그 $TAG 가 엔진 버전 v$ENGINE(시험판은 v$ENGINE-rc.<N>)과 다르다"
    # 룰 버전 — 주석 태그의 메시지 첫 줄(태그를 만들기 전이면 --rules).
    RULES=$RULES_ARG
    if line=$(git for-each-ref --format='%(objecttype)%09%(contents:subject)' "refs/tags/$TAG") && [ -n "$line" ]; then
        [ "${line%%$'\t'*}" = tag ] || fail "v 태그 $TAG 가 주석 태그가 아니다 — 룰 버전을 메시지 첫 줄 '프로그램 $ENGINE · 룰 <룰 버전>' 에 적는다(bash ci/batch.sh engine-tag $TAG)"
        subject=${line#*$'\t'}
        [ "$(name_engine "$subject")" = "$ENGINE" ] || fail "v 태그 $TAG 의 메시지 첫 줄 '$subject' 이 '프로그램 $ENGINE · 룰 <룰 버전>' 이 아니다"
        from_tag=$(name_rules "$subject")
        [ -z "$RULES" ] || [ "$RULES" = "$from_tag" ] || fail "--rules $RULES 이 태그 메시지의 룰 버전 $from_tag 와 다르다"
        RULES=$from_tag
    fi
    [ -n "$RULES" ] || fail "v 태그의 룰 버전이 없다 — 주석 태그 메시지 첫 줄 '프로그램 $ENGINE · 룰 <룰 버전>'(bash ci/batch.sh engine-tag $TAG) · 태그 전이면 --rules"
elif [[ "$TAG" =~ ^rules-($RULES_RE)(-rc\.[0-9]+)?$ ]]; then
    KIND=rules
    RULES=${BASH_REMATCH[1]}
    [ -z "$RULES_ARG" ] || [ "$RULES_ARG" = "$RULES" ] || fail "--rules $RULES_ARG 이 태그 이름의 룰 버전 $RULES 와 다르다"
else
    fail "태그 $TAG 는 v<엔진 버전> 도 rules-<룰 버전> 도 아니다"
fi
[[ "$RULES" =~ ^$RULES_RE$ ]] || fail "룰 버전 '$RULES' 의 꼴이 틀렸다 — YYYY.MM.DD(같은 날 둘째부터 .2)"

# 룰 버전의 날이 오늘(KST)+1 을 넘지 않는다 — 2062 같은 오타는 그날까지 다음 출시를 모두 막는다. Git Bash 의 `TZ=` 는
# 시각을 바꾸지 않아 UTC 에 9시간을 더해 센다.
[ -n "$TODAY" ] || TODAY=$(date -u -d '+9 hours' +%Y-%m-%d)
limit=$(date -u -d "$TODAY +1 day" +%Y-%m-%d)
day=${RULES:0:10}
day=${day//./-}
[[ ! "$day" > "$limit" ]] || fail "룰 버전 $RULES 의 날($day)이 오늘(KST $TODAY)보다 하루 넘게 늦다"

# 태그가 이미 있으면 이 커밋을 가리켜야 한다 — 다시 돌릴 때(워크플로 재실행 · 시험판 커밋에 민 정식 태그)는 그렇고, 다른 커밋의
# 같은 이름은 엉뚱한 나무를 낸다.
if have=$(git rev-parse -q --verify "refs/tags/$TAG^{commit}"); then
    [ "$have" = "$(git rev-parse "$REF^{commit}")" ] || fail "태그 $TAG 는 이미 다른 커밋(${have:0:12})에 있다"
fi

if [ "$NO_PREV" = 1 ]; then
    echo "지난 공개본 없이 꼴만 봤다($TAG · 엔진 $ENGINE · 룰 $RULES)"
    exit 0
fi
if [ -z "$PREV" ]; then
    command -v gh >/dev/null || fail "gh 가 없다 — --prev <지금 Latest 의 태그> --prev-name '<그 Release 이름>' 을 준다"
    got=$(gh release view --json tagName,name --jq '.tagName + "\t" + .name' 2>/dev/null) ||
        fail "지금 Latest 를 읽지 못했다(gh release view) — gh 로그인 · GH_TOKEN 을 보거나 --prev · --prev-name 을 준다"
    PREV=${got%%$'\t'*}
    PREV_NAME=${got#*$'\t'}
fi
[ -n "$PREV_NAME" ] || fail "--prev 를 주면 그 Release 의 이름 --prev-name 도 준다"
[[ "$PREV" =~ ^(v$ENGINE_RE|rules-$RULES_RE)$ ]] || fail "지난 공개본 $PREV 가 정식 태그(v<엔진 버전> · rules-<룰 버전>)의 꼴이 아니다"
PREV_ENGINE=$(name_engine "$PREV_NAME")
PREV_RULES=$(name_rules "$PREV_NAME")
[ -n "$PREV_ENGINE" ] && [ -n "$PREV_RULES" ] || fail "지난 공개본 $PREV 의 이름 '$PREV_NAME' 이 '프로그램 <엔진> · 룰 <룰>' 꼴이 아니다"
case "$PREV" in
    v*) [ "$PREV" = "v$PREV_ENGINE" ] || fail "지난 공개본 $PREV 와 그 이름의 엔진 $PREV_ENGINE 이 다르다" ;;
    *) [ "$PREV" = "rules-$PREV_RULES" ] || fail "지난 공개본 $PREV 와 그 이름의 룰 $PREV_RULES 이 다르다" ;;
esac
git rev-parse -q --verify "refs/tags/$PREV^{commit}" >/dev/null || fail "지난 공개본의 태그 $PREV 가 이 저장소에 없다 — git fetch --tags origin"
git merge-base --is-ancestor "$PREV" "$REF" || fail "지금 Latest($PREV)가 이 커밋의 조상이 아니다 — 새 출시가 Latest 의 룰을 빠뜨린다. main 의 머리에서 낸다"

if rules_same "$PREV" "$REF"; then rules_changed=0; else rules_changed=1; fi
if [ "$KIND" = engine ]; then
    # 엔진이 바뀌었는가는 Latest 가 싣는 엔진의 태그와 견준다 — 룰 출시의 태그 나무에는 공개 전 엔진 소스가 들 수 있다.
    git rev-parse -q --verify "refs/tags/v$PREV_ENGINE^{commit}" >/dev/null || fail "Latest 가 싣는 엔진의 태그 v$PREV_ENGINE 가 없다 — git fetch --tags origin"
    if engine_same "v$PREV_ENGINE" "$REF"; then fail "엔진이 v$PREV_ENGINE 와 같다 — 룰만 바뀌었으면 rules-<룰 버전> 으로 낸다"; fi
    higher "$PREV_ENGINE" "$ENGINE" || fail "엔진 버전 $ENGINE 이 Latest 가 싣는 엔진 $PREV_ENGINE 보다 높지 않다"
    SHIP=$ENGINE
else
    [ "$rules_changed" = 1 ] || fail "룰이 Latest($PREV)와 같다 — 낼 것이 없다"
    SHIP=$PREV_ENGINE
fi
if [ "$rules_changed" = 1 ]; then
    higher "$PREV_RULES" "$RULES" || fail "룰이 바뀌었는데 룰 버전 $RULES 이 Latest($PREV)의 $PREV_RULES 보다 높지 않다"
else
    [ "$RULES" = "$PREV_RULES" ] || fail "룰이 Latest($PREV)와 같은데 룰 버전을 $PREV_RULES → $RULES 로 바꿨다"
fi

# 배포 워크플로가 받아 쓴다 — 사람이 읽는 아래 줄을 파싱하지 않게 따로 낸다.
if [ -n "${GITHUB_OUTPUT:-}" ]; then
    {
        echo "prev=$PREV"
        echo "prev_engine=$PREV_ENGINE"
        echo "engine=$SHIP"
        echo "rules=$RULES"
    } >>"$GITHUB_OUTPUT"
fi
echo "버전 OK — $TAG · 지난 공개본(Latest) $PREV · 싣는 엔진 $SHIP · 룰 $PREV_RULES → $RULES"
