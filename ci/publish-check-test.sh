#!/bin/bash
# 공개 확인(ci/publish-check.sh)의 음성 시험 — 칸 a ~ j 마다 깨뜨린 입력을 주고 그 칸에서 멈추는지, 노출 시간이 60분을 넘으면
# '모아 내기 멈춤' 이슈를 여는지 본다(2026-11-22 · 목표 remedy_하루30건 기준 7 (가) — 게이트마다 일부러 깨뜨린 입력).
# 공개 뒤 익명 확인(testbed/harness/linux/release-anon-check.sh)도 본다(2026-11-25) — latest 를 묻는 줄이 익명 한도에 걸리면
# 알려 준 만큼 기다렸다 다시 묻는가 · 끝까지 막히면 그 칸들만 토큰으로 묻는가(받기는 익명) · 토큰 없이 막히거나, 받은 latest 가
# 다른 태그 · 불변 아님 · 초안 · 시험판 · 자산 셋 아님이거나, 받은 바이트가 다르면 실패하는가.
#
#   bash ci/publish-check-test.sh      저장소 루트 · jq · git · GNU date 가 드는 곳(CI 의 리눅스 잡)
#
# 진짜 GitHub 에 닿지 않는다 — 경로 앞에 둔 가짜 `gh` 가 시험 폴더의 JSON 에 진짜 jq 를 건다(gh 의 --jq 는 jq -r 꼴로 낸다).
# 익명 확인은 가짜 `curl` · `sleep` 이 장면 폴더의 파일로 답한다(기다리지 않고 기다린 초만 적는다).
# 저장소는 임시로 짓는다(태그 둘 · 조각 하나 · 점검 룰 하나). 버전 검사(ci/version-check.sh)는 그 저장소 안의 대역이 대신한다 —
# 버전 검사 자신은 ci/version-check-test.sh 가 본다.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CHECK="$HERE/publish-check.sh"
command -v jq >/dev/null || { echo "jq 가 없다 — 이 시험은 jq 가 드는 곳(CI 의 리눅스 잡)에서 돈다" >&2; exit 2; }

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
BIN="$W/bin"
mkdir -p "$BIN"

# ── 가짜 gh ──────────────────────────────────────────────────────────────────────────────────────
cat >"$BIN/gh" <<'GH'
#!/bin/bash
set -euo pipefail
F=${FAKE:?}
jqf=""
args=()
while [ $# -gt 0 ]; do
    case "$1" in
        --jq) jqf=$2; shift 2 ;;
        *) args+=("$1"); shift ;;
    esac
done
set -- "${args[@]}"
out() { if [ -n "$jqf" ]; then jq -r "$jqf" <"$1"; else cat "$1"; fi; }
opt() { local k=$1; shift; while [ $# -gt 0 ]; do if [ "$1" = "$k" ]; then echo "$2"; return; fi; shift; done; }
case "$1 ${2:-}" in
    "api "*/releases*) out "$F/releases.json" ;;
    "api "*/pulls)
        sha=${2#*/commits/}
        sha=${sha%/pulls}
        if [ -f "$F/pulls-$sha.json" ]; then out "$F/pulls-$sha.json"; else out "$F/pulls-none.json"; fi
        ;;
    "run list") out "$F/runs-$(opt --workflow "$@")-$(opt --event "$@").json" ;;
    "run view") out "$F/run-$3.json" ;;
    "release download") cp "$F/assets/"* "$(opt --dir "$@")/" ;;
    "release view") out "$F/latest.json" ;;
    "issue list") out "$F/issues.json" ;;
    "issue create") echo "$*" >>"$F/created.txt" ;;
    *) echo "가짜 gh: 모르는 부름 — $*" >&2; exit 9 ;;
esac
GH
chmod +x "$BIN/gh"

# ── 임시 저장소 — Latest(rules-2026.11.21.3) 위에 새 태그(rules-2026.11.22) ──────────────────────────
R="$W/repo"
mkdir -p "$R/ci" "$R/plugins/a" "$R/docs/changes"
cd "$R"
git -c init.defaultBranch=main init -q .
printf 'id: a\nkind: check\nplatforms: [linux]\n' >plugins/a/plugin.yaml
printf '#!/bin/bash\n[ -z "${FAIL_VERSION:-}" ] || { echo "버전 검사 대역: 실패"; exit 1; }\necho "버전 검사 대역: 통과"\n' >ci/version-check.sh
git add -A && git -c user.email=t@t -c user.name=t commit -qm latest
git tag rules-2026.11.21.3
printf -- '---\nrules: [a]\n---\n* **바뀐 것** 시험\n' >docs/changes/a-0.2.md
git add -A && git -c user.email=t@t -c user.name=t commit -qm new
git tag rules-2026.11.22
NEW_SHA=$(git rev-parse rules-2026.11.22)
FRAG_SHA=$NEW_SHA
TAG=rules-2026.11.22

# 자산 셋과 그 목록 · 열쇠
A="$W/assets"
mkdir -p "$A"
printf 'linux\n' >"$A/remedy-linux-x64.tar.gz"
printf 'windows\n' >"$A/remedy-windows-x64.zip"
(cd "$A" && sha256sum remedy-linux-x64.tar.gz remedy-windows-x64.zip >SHA256SUMS)
sha() { sha256sum <"$A/$1" | cut -d' ' -f1; }
ASSETS="remedy-linux-x64.tar.gz:$(sha remedy-linux-x64.tar.gz) remedy-windows-x64.zip:$(sha remedy-windows-x64.zip) SHA256SUMS:$(sha SHA256SUMS)"
KEY=$(printf '%s' "$ASSETS" | sha256sum | cut -d' ' -f1)

# ── 맞는 장면 — 시험마다 이것을 베껴 한 칸을 깨뜨린다 ────────────────────────────────────────────
GOOD="$W/good"
mkdir -p "$GOOD/assets"
cp "$A/"* "$GOOD/assets/"
asset_json() { printf '{"name":"%s","uploader":{"login":"github-actions[bot]"},"digest":"sha256:%s"}' "$1" "$(sha "$1")"; }
cat >"$GOOD/releases.json" <<EOF
[{"tag_name":"$TAG","draft":true,"prerelease":false,"author":{"login":"github-actions[bot]"},
  "name":"프로그램 1.25.3 · 룰 2026.11.22","body":"## 1. 실행\n## 2. 변경 내용\n본문",
  "assets":[$(asset_json remedy-linux-x64.tar.gz),$(asset_json remedy-windows-x64.zip),$(asset_json SHA256SUMS)]},
 {"tag_name":"rules-2026.11.21.3","draft":false,"prerelease":false,"author":{"login":"github-actions[bot]"},"name":"프로그램 1.25.3 · 룰 2026.11.21.3","body":"","assets":[]}]
EOF
printf '[{"headBranch":"%s","conclusion":"success"}]\n' "$TAG" >"$GOOD/runs-release.yml-push.json"
printf '[]\n' >"$GOOD/runs-release.yml-workflow_dispatch.json"
printf '[{"databaseId":7,"headSha":"%s","displayTitle":"점검 %s %s","conclusion":"success"}]\n' "$NEW_SHA" "$TAG" "$KEY" \
    >"$GOOD/runs-checks.yml-workflow_dispatch.json"
printf '{"jobs":[{"name":"linux","conclusion":"success"},{"name":"windows","conclusion":"success"}]}\n' >"$GOOD/run-7.json"
printf '[{"status":"completed","conclusion":"success"}]\n' >"$GOOD/runs-ci.yml-push.json"
printf '{"tagName":"rules-2026.11.21.3","name":"프로그램 1.25.3 · 룰 2026.11.21.3"}\n' >"$GOOD/latest.json"
printf '[]\n' >"$GOOD/issues.json"
printf '[]\n' >"$GOOD/pulls-none.json"

PASS=0
BAD=0
t() { if [ "$2" = "$3" ]; then PASS=$((PASS + 1)); echo "통과  $1"; else BAD=$((BAD + 1)); echo "실패  $1 — '$2'(기대 '$3')"; fi; }

# 장면 하나를 지어 공개 확인을 돌린다 — 끝의 인자는 장면을 바꾸는 셸 한 줄(장면 폴더 안에서 돈다).
run() { # 이름 · 태그 · dry · checks · 자산 목록 · 바꾸는 셸
    local name=$1 tag=$2 dry=$3 checks=$4 assets=$5 change=${6:-}
    local f="$W/case-$name"
    rm -rf "$f" && cp -r "$GOOD" "$f"
    (cd "$f" && eval "$change")
    # 멈추는 것이 기대인 경우가 많다 — 종료 코드가 아니라 출력(멈춘 칸)을 본다.
    (cd "$R" && FAKE="$f" GH_REPO=t/r PATH="$BIN:$PATH" bash "$CHECK" "$tag" "$assets" "$dry" "$W/dl-$name" "$checks") \
        >"$W/out-$name.txt" 2>&1 || true
}
# 멈춘 칸 — '::error::<칸> …' 의 첫 글자(멈추지 않았으면 '통과').
stopped() { if grep -q "최종 확인 통과" "$W/out-$1.txt"; then echo 통과; else sed -n 's/^::error::\([a-j]\) .*/\1/p' "$W/out-$1.txt" | head -1; fi; }

edit_rel() { jq "$1" releases.json >releases.json.new && mv releases.json.new releases.json; }

run good "$TAG" false runner "$ASSETS" ""
t "맞는 장면은 지난다" "$(stopped good)" 통과
run a "$TAG-rc.1" false runner "$ASSETS" ""
t "a 시험판 태그를 정식으로" "$(stopped a)" a
run b1 "$TAG" false runner "$ASSETS" "edit_rel '(.[0].draft) = false'"
t "b 초안이 아니다" "$(stopped b1)" b
run b2 "$TAG" false runner "$ASSETS" "edit_rel '(.[0].author.login) = \"someone\"'"
t "b 배포 워크플로가 만들지 않았다" "$(stopped b2)" b
run c "$TAG" false runner "$ASSETS" "printf '[{\"headBranch\":\"$TAG\",\"conclusion\":\"failure\"}]' >runs-release.yml-push.json"
t "c 배포 실행이 실패했다" "$(stopped c)" c
run d1 "$TAG" false runner "${ASSETS/remedy-linux-x64.tar.gz:/remedy-linux-x64.tar.gz:00}" ""
t "d 자산 해시가 점검한 파일과 다르다" "$(stopped d1)" d
run d2 "$TAG" false runner "$ASSETS" "printf 'changed\n' >assets/remedy-windows-x64.zip"
t "d 받은 자산의 바이트가 바뀌었다" "$(stopped d2)" d
run d3 "$TAG" false runner "$ASSETS" "edit_rel '(.[0].assets[0].uploader.login) = \"someone\"'"
t "d 자산을 다른 이가 올렸다" "$(stopped d3)" d
run e1 "$TAG" false runner "$ASSETS" "edit_rel '(.[0].body) = \"<!-- remedy:notes-pending -->\"'"
t "e 본문이 아직 표지다" "$(stopped e1)" e
run e2 "$TAG" false runner "$ASSETS" "edit_rel '(.[0].body) = \"## 2. {{조각}}\"'"
t "e 본문에 채우지 못한 자리" "$(stopped e2)" e
FAIL_VERSION=1 run f1 "$TAG" false runner "$ASSETS" ""
t "f 버전 검사가 실패하면 멈춘다(종료 0 아님)" "$(grep -c '^f 버전 검사 대역: 실패' "$W/out-f1.txt")/$(grep -c '최종 확인 통과' "$W/out-f1.txt")" 1/0
run f2 "$TAG" false runner "$ASSETS" "edit_rel '(.[0].name) = \"프로그램 1.25.2 · 룰 2026.11.22\"'"
t "f 초안이 실은 엔진이 지금 Latest 와 다르다" "$(stopped f2)" f
run g "$TAG" false runner "$ASSETS" "edit_rel '. + [{\"tag_name\":\"v1.26.0\",\"draft\":true}]'"
t "g 엔진 출시가 진행 중이다" "$(stopped g)" g
run h "$TAG" false runner "$ASSETS" "printf '[{\"status\":\"completed\",\"conclusion\":\"failure\"}]' >runs-ci.yml-push.json"
t "h 태그 커밋의 main CI 가 실패했다" "$(stopped h)" h
run i1 "$TAG" false runner "$ASSETS" "printf '[]' >runs-checks.yml-workflow_dispatch.json"
t "i 러너 점검 실행이 없다" "$(stopped i1)" i
run i2 "$TAG" false runner "$ASSETS" "sed -i 's/$KEY/0000/' runs-checks.yml-workflow_dispatch.json"
t "i 다른 자산 셋(열쇠)으로 돈 점검" "$(stopped i2)" i
run i3 "$TAG" false runner "$ASSETS" "sed -i 's/$NEW_SHA/$(git -C "$R" rev-parse rules-2026.11.21.3)/' runs-checks.yml-workflow_dispatch.json"
t "i 다른 커밋에서 돈 점검" "$(stopped i3)" i
run i4 "$TAG" false runner "$ASSETS" "sed -i 's/\"windows\",\"conclusion\":\"success\"/\"windows\",\"conclusion\":\"failure\"/' run-7.json"
t "i 잡 하나가 실패한 점검" "$(stopped i4)" i
run i5 "$TAG" false local "$ASSETS" "printf '[]' >runs-checks.yml-workflow_dispatch.json"
t "i 점검 자리가 local 이면 러너 실행을 보지 않는다" "$(stopped i5)" 통과
run j "$TAG" false runner "$ASSETS" "printf '[{\"number\":9,\"title\":\"모아 내기 멈춤 — rules-2026.11.21.3\"}]' >issues.json"
t "j 모아 내기 멈춤 이슈가 열려 있다" "$(stopped j)" j

# ── 노출 시간 — 조각을 들인 PR 을 연 때 → 공개 ───────────────────────────────────────────────────
exposure() { # 이름 · PR 을 연 때(없으면 PR 을 못 찾음)
    local f="$W/exp-$1"
    rm -rf "$f" && cp -r "$GOOD" "$f"
    if [ -n "$2" ]; then printf '[{"number":5,"created_at":"%s"}]\n' "$2" >"$f/pulls-$FRAG_SHA.json"; fi
    (cd "$R" && FAKE="$f" GH_REPO=t/r PATH="$BIN:$PATH" bash "$CHECK" --exposure "$TAG" 2026-11-22T10:00:00Z rules-2026.11.21.3) \
        >"$W/exp-out-$1.txt" 2>&1 || true
    if [ -f "$f/created.txt" ]; then echo 이슈; else echo 없음; fi
}
t "노출 59분 — 이슈를 열지 않는다" "$(exposure in 2026-11-22T09:01:00Z)" 없음
t "노출 61분 — '모아 내기 멈춤' 이슈를 연다" "$(exposure over 2026-11-22T08:59:00Z)" 이슈
t "점검 룰의 PR 을 못 찾으면 넘은 것으로 센다" "$(exposure nopr '')" 이슈

# ── 공개 뒤 익명 확인 — latest 의 한도 · 토큰 길 · 받은 바이트 ─────────────────────────────────────────
# 가짜 curl: API 는 익명으로 물을 때마다 anon.txt 의 다음 줄(넘으면 마지막 줄), 토큰을 실으면 token.txt 의 줄로 답한다 — 줄은
# '<상태> <remaining> <reset 까지 초> <retry-after>'(- 는 그 머리 줄 없음) · 200 이면 본문은 latest.json(토큰은 token-latest.json).
# 받기는 dl/ 의 파일. 부를 때마다 calls.txt 에 한 줄(토큰을 실은 길 — stdin · argv · no). 가짜 sleep 은 초를 slept.txt 에 적는다.
ANON="$(cd "$HERE/.." && pwd)/testbed/harness/linux/release-anon-check.sh"
ABIN="$W/anon-bin"
mkdir -p "$ABIN"
cat >"$ABIN/curl" <<'CURL'
#!/bin/bash
set -euo pipefail
F=${FAKE:?}
out="" dump="" fmt="" url="" auth=no
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out=$2; shift 2 ;;
        -D) dump=$2; shift 2 ;;
        -w) fmt=$2; shift 2 ;;
        -H)
            if [ "$2" = @- ]; then
                if grep -q '^Authorization: Bearer .'; then auth=stdin; fi
            else
                case "$2" in [Aa]uthorization:*) auth=argv ;; esac
            fi
            shift 2
            ;;
        -*) shift ;;
        *) url=$1; shift ;;
    esac
done
case "$url" in
    https://api.github.com/*/releases/latest)
        if [ "$auth" != no ]; then
            echo "api token $auth" >>"$F/calls.txt"
            spec=$(cat "$F/token.txt")
            body="$F/token-latest.json"
        else
            echo "api anon" >>"$F/calls.txt"
            spec=$(sed -n "$(grep -c '^api anon' "$F/calls.txt")p" "$F/anon.txt")
            [ -n "$spec" ] || spec=$(tail -n 1 "$F/anon.txt")
            body="$F/latest.json"
        fi
        read -r code remaining reset retry <<<"$spec"
        # HTTP/1.1 꼴 — 이름이 대소문자 섞임 · 줄 끝 CRLF(Git Bash 의 curl 이 받는 꼴)
        if [ -n "$dump" ]; then
            {
                printf 'HTTP/1.1 %s\r\n' "$code"
                [ "$remaining" = - ] || printf 'X-RateLimit-Remaining: %s\r\n' "$remaining"
                [ "$reset" = - ] || printf 'X-RateLimit-Reset: %s\r\n' "$(($(date +%s) + reset))"
                [ "$retry" = - ] || printf 'Retry-After: %s\r\n' "$retry"
                printf '\r\n'
            } >"$dump"
        fi
        if [ "$code" = 200 ]; then cp "$body" "$out"; else printf '{"message":"API rate limit exceeded"}\n' >"$out"; fi
        ;;
    https://github.com/*/releases/*)
        echo "dl $auth ${url##*/}" >>"$F/calls.txt"
        cp "$F/dl/${url##*/}" "$out"
        code=200
        ;;
    *) echo "가짜 curl: 모르는 주소 — $url" >&2; exit 9 ;;
esac
[ -z "$fmt" ] || printf '%s' "$code"
CURL
cat >"$ABIN/sleep" <<'SLEEP'
#!/bin/bash
echo "$1" >>"${FAKE:?}/slept.txt"
SLEEP
chmod +x "$ABIN/curl" "$ABIN/sleep"

# latest 의 답 — API 의 꼴(들여 쓴 JSON · 자산마다 browser_download_url 한 줄). 태그 하나를 받는다.
release_json() {
    local a sep=""
    printf '{\n  "tag_name": "%s",\n  "draft": false,\n  "prerelease": false,\n  "immutable": true,\n  "assets": [' "$1"
    for a in remedy-linux-x64.tar.gz remedy-windows-x64.zip SHA256SUMS; do
        printf '%s\n    {\n      "name": "%s",\n      "browser_download_url": "https://github.com/t/r/releases/download/%s/%s"\n    }' \
            "$sep" "$a" "$1" "$a"
        sep=","
    done
    printf '\n  ]\n}\n'
}
# 맞는 장면 — 익명 200 · 공개한 태그 · 받기는 점검한 파일($A) 그대로.
AGOOD="$W/anon-good"
mkdir -p "$AGOOD/dl"
cp "$A/"* "$AGOOD/dl/"
release_json "$TAG" >"$AGOOD/latest.json"
cp "$AGOOD/latest.json" "$AGOOD/token-latest.json"
echo "200 59 3600 -" >"$AGOOD/anon.txt"
echo "200 4999 3600 -" >"$AGOOD/token.txt"
: >"$AGOOD/calls.txt"
: >"$AGOOD/slept.txt"

# 장면 하나 — 이름 · GH_TOKEN(빈 값이면 없음) · 바꾸는 셸(장면 폴더 안에서 돈다). 한 줄로 낸다: 종료 · 확인한 길 · 익명과 토큰으로
# 물은 수 · 기다린 합 · 받기(익명/모두).
anon() {
    local f="$W/anon-$1" rc=0 p
    rm -rf "$f" && cp -r "$AGOOD" "$f"
    (cd "$f" && eval "${3:-}")
    (cd "$f" && FAKE="$f" GH_TOKEN="$2" GITHUB_REPOSITORY=t/r PATH="$ABIN:$PATH" bash "$ANON" "$TAG" "$A" "$f/work") \
        >"$f/out.txt" 2>&1 || rc=$?
    p=$(sed -n 's/^확인한 길: \([^(]*\)(.*/\1/p' "$f/out.txt")
    echo "종료 $rc · 길 ${p:-없음} · 익명 $(grep -c '^api anon' "$f/calls.txt" || true) · 토큰 $(grep -c '^api token' "$f/calls.txt" || true)" \
        "· 기다림 $(awk '{ s += $1 } END { print s + 0 }' "$f/slept.txt")" \
        "· 받기 익명 $(grep -c '^dl no ' "$f/calls.txt" || true)/$(grep -c '^dl ' "$f/calls.txt" || true)"
}
t "익명 200 — 기다리지 않고 토큰도 쓰지 않는다(토큰이 있어도)" "$(anon ok tok)" "종료 0 · 길 익명 · 익명 1 · 토큰 0 · 기다림 0 · 받기 익명 6/6"
# reset 까지의 초는 가짜와 스크립트가 시각을 따로 읽어 1 ~ 2초 갈린다.
t "한도(403 · remaining 0 · reset 90초 뒤) — reset 까지 기다렸다 다시 물어 지난다" \
    "$(anon reset '' "printf '403 0 90 -\n200 59 3600 -\n' >anon.txt" | sed -E 's/기다림 (8[5-9]|9[01]) /기다림 약90 /')" \
    "종료 0 · 길 익명 · 익명 2 · 토큰 0 · 기다림 약90 · 받기 익명 6/6"
t "그 기록 — 상태 · remaining · reset · retry-after 줄" \
    "$(grep -c '^  익명 1번째 — HTTP 403 · remaining 0 · reset [0-9]*([0-9]*초 뒤) · retry-after 없음$' "$W/anon-reset/out.txt" || true)" 1
# remaining 0 은 상태와 상관없이 한도다 — reset 전에 다시 물으면 걸린다.
t "remaining 0(HTTP 500 · reset 90초 뒤) — 403 · 429 가 아니어도 reset 까지 기다렸다 다시 물어 지난다" \
    "$(anon zero '' "printf '500 0 90 -\n200 59 3600 -\n' >anon.txt" | sed -E 's/기다림 (8[5-9]|9[01]) /기다림 약90 /')" \
    "종료 0 · 길 익명 · 익명 2 · 토큰 0 · 기다림 약90 · 받기 익명 6/6"
t "한도(429 · retry-after 30) — 30초 기다렸다 다시 물어 지난다" "$(anon retry '' "printf '429 - - 30\n200 58 3600 -\n' >anon.txt")" \
    "종료 0 · 길 익명 · 익명 2 · 토큰 0 · 기다림 30 · 받기 익명 6/6"
t "한 번에 120초까지 — retry-after 200 이면 120초 기다렸다 다시 묻는다" "$(anon once '' "printf '429 - - 200\n200 58 3600 -\n' >anon.txt")" \
    "종료 0 · 길 익명 · 익명 2 · 토큰 0 · 기다림 120 · 받기 익명 6/6"
t "알려 준 때가 없는 403 — 1분 기다렸다 다시 묻는다" "$(anon default '' "printf '403 - - -\n200 58 3600 -\n' >anon.txt")" \
    "종료 0 · 길 익명 · 익명 2 · 토큰 0 · 기다림 60 · 받기 익명 6/6"
t "retry-after 0 — 10초보다 짧게는 기다리지 않는다" "$(anon floor '' "printf '429 - - 0\n200 58 3600 -\n' >anon.txt")" \
    "종료 0 · 길 익명 · 익명 2 · 토큰 0 · 기다림 10 · 받기 익명 6/6"
t "끝까지 막힘(403 · retry-after 100 거듭) — 합 300초를 기다린 뒤 토큰 길로 지난다" "$(anon wait tok "echo '403 - - 100' >anon.txt")" \
    "종료 0 · 길 토큰 · 익명 4 · 토큰 1 · 기다림 300 · 받기 익명 6/6"
t "그 기록 — 확인한 길 · 토큰은 표준 입력으로만 싣는다" \
    "$(grep -c '^확인한 길: 토큰(GH_TOKEN) — 익명 한도(HTTP 403 ' "$W/anon-wait/out.txt" || true)/$(grep -c '^api token stdin$' "$W/anon-wait/calls.txt" || true)" 1/1
t "reset 이 상한 밖(remaining 0 · 3000초 뒤) — 기다리지 않고 토큰 길로 지난다" "$(anon far tok "echo '403 0 3000 -' >anon.txt")" \
    "종료 0 · 길 토큰 · 익명 1 · 토큰 1 · 기다림 0 · 받기 익명 6/6"
t "익명 200 의 답에 칸이 없다 — 기다리지 않고 토큰 길로 지난다" "$(anon nofield tok "echo '{\"message\":\"x\"}' >latest.json")" \
    "종료 0 · 길 토큰 · 익명 1 · 토큰 1 · 기다림 0 · 받기 익명 6/6"
# GitHub 은 curl 이 아닌 User-Agent 에 한 줄 JSON 을 준다 — 줄 수로 세면 자산이 하나다.
t "토큰 길의 답이 한 줄 JSON — 자산 셋을 센다" \
    "$(anon compact tok "echo '403 0 3000 -' >anon.txt; tr -d '\n ' <token-latest.json >c.json; mv c.json token-latest.json")" \
    "종료 0 · 길 토큰 · 익명 1 · 토큰 1 · 기다림 0 · 받기 익명 6/6"
t "끝까지 막히고 GH_TOKEN 이 없다 — 실패" "$(anon notok '' "echo '403 0 3000 -' >anon.txt")" \
    "종료 1 · 길 없음 · 익명 1 · 토큰 0 · 기다림 0 · 받기 익명 6/6"
t "그 까닭 줄" "$(grep -c '^  latest 를 확인하지 못했다 — 익명 한도(HTTP 403 .*GH_TOKEN 이 없어 토큰으로 묻지 못했다$' "$W/anon-notok/out.txt" || true)" 1
t "토큰 길의 latest 가 다른 태그 — 실패" \
    "$(anon other tok "echo '403 0 3000 -' >anon.txt; release_json rules-2026.11.21.3 >token-latest.json")" \
    "종료 1 · 길 토큰 · 익명 1 · 토큰 1 · 기다림 0 · 받기 익명 6/6"
t "그 까닭 — latest 가 그 태그가 아니다" "$(grep -c "^  latest 가 $TAG 가 아니다\$" "$W/anon-other/out.txt" || true)" 1
# 받은 답의 나머지 판정 — 불변 · 초안 · 시험판은 익명 200 의 답을, 자산 수는 토큰 길의 한 줄 답(자산 둘)을 바꾼다. 받은 답이
# 틀린 것은 토큰 길로 다시 묻지 않는다(토큰이 있어도 토큰 0).
t "익명 latest 가 불변이 아니다 — 실패" \
    "$(anon mutable tok "jq '.immutable = false' latest.json >j.json && mv j.json latest.json")" \
    "종료 1 · 길 익명 · 익명 1 · 토큰 0 · 기다림 0 · 받기 익명 6/6"
t "그 까닭 — 불변이 아니다" "$(grep -c '^  불변이 아니다$' "$W/anon-mutable/out.txt" || true)" 1
t "익명 latest 가 초안이다 — 실패" \
    "$(anon draft tok "jq '.draft = true' latest.json >j.json && mv j.json latest.json")" \
    "종료 1 · 길 익명 · 익명 1 · 토큰 0 · 기다림 0 · 받기 익명 6/6"
t "그 까닭 — 아직 초안이다" "$(grep -c '^  아직 초안이다$' "$W/anon-draft/out.txt" || true)" 1
t "익명 latest 가 시험판이다 — 실패" \
    "$(anon pre tok "jq '.prerelease = true' latest.json >j.json && mv j.json latest.json")" \
    "종료 1 · 길 익명 · 익명 1 · 토큰 0 · 기다림 0 · 받기 익명 6/6"
t "그 까닭 — 시험판이다" "$(grep -c '^  시험판이다$' "$W/anon-pre/out.txt" || true)" 1
t "토큰 길의 한 줄 답에 자산이 둘 — 실패" \
    "$(anon two tok "echo '403 0 3000 -' >anon.txt; jq -c 'del(.assets[2])' token-latest.json >j.json && mv j.json token-latest.json")" \
    "종료 1 · 길 토큰 · 익명 1 · 토큰 1 · 기다림 0 · 받기 익명 6/6"
t "그 까닭 — 자산 수 2 · 셋이 아니다" \
    "$(grep -c -e '^자산 수: 2$' -e '^  자산이 셋이 아니다$' "$W/anon-two/out.txt" || true)" 2
t "토큰 길도 막힘(401) — 실패" "$(anon tokfail tok "echo '403 0 3000 -' >anon.txt; echo '401 - - -' >token.txt")" \
    "종료 1 · 길 없음 · 익명 1 · 토큰 1 · 기다림 0 · 받기 익명 6/6"
t "받은 바이트가 점검한 파일과 다르다 — 실패" "$(anon bytes tok "printf 'changed\n' >dl/remedy-windows-x64.zip")" \
    "종료 1 · 길 익명 · 익명 1 · 토큰 0 · 기다림 0 · 받기 익명 6/6"
t "그 까닭 — 두 주소 꼴 모두 '다르다'" \
    "$(grep -c '^  200 다르다  https://github.com/t/r/releases/.*/remedy-windows-x64.zip$' "$W/anon-bytes/out.txt" || true)" 2

echo "--- 통과 $PASS · 실패 $BAD"
[ "$BAD" = 0 ]
