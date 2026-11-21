#!/bin/bash
# 공개 워크플로(.github/workflows/publish.yml)의 확인 — 공개 전 최종 확인과 공개 뒤 노출 시간(2026-11-21).
#
#   bash ci/publish-check.sh <태그> '<이름:sha256> …' <true|false(시험)> <받을 폴더>
#   bash ci/publish-check.sh --exposure <태그> <공개 시각 RFC3339> <지난 Latest 의 태그>
#
# 잡 안에서 돈다(GH_TOKEN · GH_REPO). 최종 확인의 칸 a ~ h 는 그 워크플로 첫머리에 있다 — 하나라도 어긋나면 종료 1 이고 공개하지
# 않는다. 받을 폴더에는 초안의 자산 셋을 받아 둔다(공개 뒤 익명 확인이 그 바이트와 견준다).
#
# 노출 시간은 이 출시가 새로 실은 업데이트 내역 조각마다 그 조각을 들인 PR 을 연 때 → 공개다(AGENTS.md *배포 전 룰은 올리지
# 않는다* 의 예외 — 공개된 공지에 근거한 취약점 점검 룰). 60분을 넘긴 점검 룰이 있으면 '모아 내기 멈춤 — <태그>' 이슈를 연다 —
# 그 이슈가 열린 동안 `ci/batch.sh` 는 다음 묶음을 시작하지 않는다(사람이 까닭을 적고 닫는다). 표는 stdout(잡 요약)에 쓴다.
set -euo pipefail
fail() { echo "::error::$*"; exit 1; }
RULES_RE='[0-9]{4}\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])(\.([2-9]|[1-9][0-9]+))?'
LIMIT_MIN=60

exposure() {
    local tag=$1 published=$2 prev=$3 pub_s path sha pr opened mins rules id over=() rows=""
    pub_s=$(date -u -d "$published" +%s)
    echo "## 보인 시간 — $tag"
    echo
    echo "| 조각 | PR | PR 을 연 때(UTC) | 보인 시간 | 룰 |"
    echo "|---|---|---|---|---|"
    while IFS= read -r path; do
        [ -n "$path" ] || continue
        case "$path" in docs/changes/README.md) continue ;; esac
        sha=$(git log --diff-filter=A --format=%H -1 "$tag" -- "$path")
        pr=$(gh api "repos/$GH_REPO/commits/$sha/pulls" --jq '.[0] | "\(.number)\t\(.created_at)"' 2>/dev/null || true)
        rules=$(git show "$tag:$path" | sed -n '2,6s/^rules: *\[\(.*\)\].*/\1/p' | tr -d ' ')
        if [ -z "$pr" ]; then
            echo "| \`$path\` | — | — | PR 없음 | $rules |"
            continue
        fi
        opened=${pr#*$'\t'}
        mins=$(( (pub_s - $(date -u -d "$opened" +%s)) / 60 ))
        echo "| \`$path\` | #${pr%%$'\t'*} | $opened | ${mins}분 | $rules |"
        # 점검 룰만 상한에 건다(악성코드 탐지 · 치료 룰은 모아 내지 않는다 — 그 규칙 그대로).
        for id in ${rules//,/ }; do
            if git show "$tag:plugins/$id/plugin.yaml" 2>/dev/null | grep -qE '^kind:[[:space:]]*check'; then
                if [ "$mins" -gt "$LIMIT_MIN" ]; then over+=("$id(#${pr%%$'\t'*} · ${mins}분)"); fi
                break
            fi
        done
    done < <(comm -13 <(git ls-tree -r --name-only "$prev" -- docs/changes | sort) <(git ls-tree -r --name-only "$tag" -- docs/changes | sort))
    echo
    if [ ${#over[@]} -gt 0 ]; then
        echo "**${LIMIT_MIN}분을 넘긴 점검 룰: ${over[*]}** — '모아 내기 멈춤' 이슈를 열었다(다음 묶음은 그 이슈를 닫을 때까지 서지 않는다)."
        gh issue create --title "모아 내기 멈춤 — $tag" --body "$(printf '%s\n' \
            "공개한 출시 $tag 에서 PR 을 연 때 → 공개가 ${LIMIT_MIN}분을 넘긴 점검 룰이 있다(AGENTS.md *배포 전 룰은 올리지 않는다* 의 예외 · 상한 ${LIMIT_MIN}분)." \
            "" "넘긴 룰: ${over[*]}" "" \
            "출시는 공개했다. 까닭(묶음이 몰렸다 · 필수 점검이 늦었다 · 승인이 늦었다 등)을 이 이슈에 적고 닫으면 bash ci/batch.sh 가 다음 묶음을 연다.")" >/dev/null
    else
        echo "모든 점검 룰이 ${LIMIT_MIN}분 안이다."
    fi
}

if [ "${1:-}" = --exposure ]; then
    [ $# = 4 ] || { echo "쓰는 법: bash ci/publish-check.sh --exposure <태그> <공개 시각> <지난 Latest>" >&2; exit 2; }
    exposure "$2" "$3" "$4"
    exit 0
fi

[ $# = 4 ] || { echo "쓰는 법: bash ci/publish-check.sh <태그> '<이름:sha256> …' <true|false> <받을 폴더>" >&2; exit 2; }
TAG=$1 ASSETS=$2 DRY=$3 DIR=$4

# a 태그의 꼴
if [[ "$TAG" =~ ^(v[0-9]+\.[0-9]+\.[0-9]+|rules-$RULES_RE)$ ]]; then rc=false
elif [ "$DRY" = true ] && [[ "$TAG" =~ ^(v[0-9]+\.[0-9]+\.[0-9]+|rules-$RULES_RE)-rc\.[0-9]+$ ]]; then rc=true
else fail "a 태그 $TAG 가 정식 꼴이 아니다(시험판은 dry_run 으로만)"; fi
echo "a 태그 $TAG — $([ "$rc" = true ] && echo 시험판 || echo 정식)"

# b 초안 · 시험판 표시 · 만든 이
rel=$(gh api "repos/$GH_REPO/releases?per_page=50" --jq ".[] | select(.tag_name == \"$TAG\")")
[ -n "$rel" ] || fail "b $TAG 의 Release 가 없다"
[ "$(jq -r .draft <<<"$rel")" = true ] || fail "b $TAG 는 초안이 아니다(이미 공개했다)"
[ "$(jq -r .prerelease <<<"$rel")" = "$rc" ] || fail "b $TAG 의 시험판 표시가 태그와 맞지 않는다"
[ "$(jq -r .author.login <<<"$rel")" = "github-actions[bot]" ] || fail "b $TAG 의 초안을 배포 워크플로가 만들지 않았다($(jq -r .author.login <<<"$rel"))"
echo "b 초안 · 시험판 표시 $rc · 만든 이 github-actions[bot]"

# c 배포 실행
ok_run() {
    gh run list --workflow release.yml --event "$1" --limit 30 --json headBranch,conclusion \
        --jq "[.[] | select(.headBranch == \"$TAG\")][0].conclusion // \"none\""
}
[ "$(ok_run push)" = success ] || fail "c $TAG 의 배포 실행(push)이 성공이 아니다: $(ok_run push)"
if [[ "$TAG" == v* ]]; then
    [ "$(ok_run workflow_dispatch)" = success ] || fail "c $TAG 의 둘째 걸음(코드서명 뒤)이 성공이 아니다: $(ok_run workflow_dispatch)"
fi
echo "c 배포 실행 성공"

# d 자산 셋 = 점검한 파일
names=$(jq -r '[.assets[].name] | sort | join(" ")' <<<"$rel")
[ "$names" = "SHA256SUMS remedy-linux-x64.tar.gz remedy-windows-x64.zip" ] || fail "d 자산이 셋이 아니다: $names"
up=$(jq -r '[.assets[].uploader.login] | unique | join(" ")' <<<"$rel")
[ "$up" = "github-actions[bot]" ] || fail "d 자산을 올린 이가 배포 워크플로만이 아니다: $up"
rm -rf "$DIR"
mkdir -p "$DIR"
gh release download "$TAG" --dir "$DIR" >/dev/null
for pair in $ASSETS; do
    name=${pair%%:*}
    want=${pair#*:}
    got=$(sha256sum "$DIR/$name" | cut -d' ' -f1)
    [ "$got" = "$want" ] || fail "d $name 의 해시가 점검한 파일과 다르다($got · 점검 $want)"
    api=$(jq -r ".assets[] | select(.name == \"$name\") | .digest // \"\"" <<<"$rel")
    [ -z "$api" ] || [ "$api" = "sha256:$got" ] || fail "d $name 의 해시가 GitHub 의 digest 와 다르다($api)"
done
[ "$(wc -w <<<"$ASSETS")" = 3 ] || fail "d 입력의 자산이 셋이 아니다: $ASSETS"
(cd "$DIR" && sha256sum -c SHA256SUMS >/dev/null) || fail "d SHA256SUMS 의 줄이 두 꾸러미와 맞지 않는다"
echo "d 자산 셋이 점검한 파일과 같다 · SHA256SUMS 가 맞다"

# e 본문
body=$(jq -r .body <<<"$rel")
! grep -q 'remedy:notes-pending' <<<"$body" || fail "e 본문이 아직 표지 한 줄이다 — 리눅스 잡의 'release notes' 걸음이 끝나지 않았다"
! grep -q '{{' <<<"$body" || fail "e 본문에 채우지 못한 자리가 있다"
echo "e 본문 $(wc -l <<<"$body")줄 · $(grep -m1 '^## 2\.' <<<"$body" || true)"

# f 버전 검사 — 지금 Latest 와 견준다(조상 · 룰 버전 · 엔진 역행).
bash ci/version-check.sh "$TAG" --ref "$TAG" | sed 's/^/f /'

# g 엔진 출시가 진행 중이면 룰 공개를 멈춘다(결정 R2).
if [[ "$TAG" == rules-* ]]; then
    engine_drafts=$(gh api "repos/$GH_REPO/releases?per_page=50" --jq '[.[] | select(.draft) | select(.tag_name | startswith("v")) | .tag_name] | join(" ")')
    [ -z "$engine_drafts" ] || fail "g 엔진 출시가 진행 중이다($engine_drafts) — 그 공개까지 룰 공개를 멈춘다"
fi
echo "g 진행 중인 엔진 출시 없음"

# h 태그 커밋의 main push CI
sha=$(git rev-parse "$TAG^{commit}")
ci=$(gh run list --workflow ci.yml --event push --commit "$sha" --json status,conclusion --jq '.[0] | "\(.status) \(.conclusion)"' 2>/dev/null || true)
case "$ci" in
    "completed failure" | "completed cancelled" | "completed timed_out") fail "h 태그 커밋(${sha:0:12})의 main CI 가 $ci 로 끝났다 — 병합 뒤 main 이 깨졌다" ;;
    "completed success") echo "h 태그 커밋의 main CI 성공" ;;
    *) echo "h 태그 커밋의 main CI: ${ci:-없음}(끝나지 않았다 — 기록만 한다)" ;;
esac
echo "최종 확인 통과 — $TAG"
