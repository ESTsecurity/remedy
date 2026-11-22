#!/bin/bash
# 공개 확인(ci/publish-check.sh)의 음성 시험 — 칸 a ~ j 마다 깨뜨린 입력을 주고 그 칸에서 멈추는지, 노출 시간이 60분을 넘으면
# '모아 내기 멈춤' 이슈를 여는지 본다(2026-11-22 · 목표 remedy_하루30건 기준 7 (가) — 게이트마다 일부러 깨뜨린 입력).
#
#   bash ci/publish-check-test.sh      저장소 루트 · jq · git · GNU date 가 드는 곳(CI 의 리눅스 잡)
#
# 진짜 GitHub 에 닿지 않는다 — 경로 앞에 둔 가짜 `gh` 가 시험 폴더의 JSON 에 진짜 jq 를 건다(gh 의 --jq 는 jq -r 꼴로 낸다).
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

echo "--- 통과 $PASS · 실패 $BAD"
[ "$BAD" = 0 ]
