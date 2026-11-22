#!/bin/bash
# 룰 PR 의 경로 제한 — 룰을 고친 PR 이 룰의 자리 밖(도구 · 하네스 바탕 · 엔진 · CI)을 함께 고치지 않는가(2026-11-22 · 목표
# remedy_하루30건 기준 7 (가)의 게이트 — 저장소 설정을 바꾸지 않고 필수 검사 linux 잡의 걸음 하나로).
#
#   bash ci/rule-scope.sh <바탕> <머리>   PR 의 바탕과 머리(CI 에서는 HEAD^1 · HEAD) — 어긋난 파일을 적고 종료 1
#   bash ci/rule-scope.sh selftest        임시 저장소로 경우를 돈다(CI)
#
# 룰 PR 은 `plugins/` 를 고친 PR 이다. 그 PR 이 고칠 수 있는 자리(docs/개발-안내.md '새 룰을 더할 때'):
#   - `plugins/` · `docs/changes/` · `docs/위협별-안내.md`
#   - 룰 하네스 — `testbed/harness/{linux,host}/` 바로 아래의 파일 가운데 머리 10줄에 `# 룰:` 줄이 있는 것(지운 것은 바탕에서
#     본다) · 하네스 픽스처(`testbed/harness/**/fixtures/`) · AI 시험 위협(`testbed/ai-exam/threats/`)
#   - 조건에 따라 더하는 자리 — 판정 기준 대조(`xtask/src/netcriteria.rs` — 룰 id 가 박혀 있다) · AI 시험의 정답 목록
#     (`xtask/src/exam.rs`) · 누출 검사의 예외(`xtask/leaks-except.txt`) · 표준 인자 밖의 하네스 단계(rc 묶음 두 스크립트)
# 그 밖(필수 점검 · 하네스 바탕 · 출시 스크립트 · 워크플로 · 엔진)은 따로 PR 로 낸다 — 필수 점검은 태그의 트리로 돌아, 룰 PR 이
# 함께 고친 도구가 다음 묶음의 게이트가 된다.
set -euo pipefail

EXTRA=(
    xtask/src/netcriteria.rs
    xtask/src/exam.rs
    xtask/leaks-except.txt
    testbed/harness/linux/rc-bundle.sh
    testbed/harness/host/Invoke-RcBundle.ps1
)

# 그 리비전에서 머리 10줄에 `# 룰:` 줄이 있는 하네스인가.
rule_harness_at() {
    git cat-file -e "$1:$2" 2>/dev/null && git show "$1:$2" | sed -n '1,10p' | grep -q '^# 룰: '
}

allowed() {
    local base=$1 head=$2 f=$3 e
    case "$f" in
        plugins/* | docs/changes/* | docs/위협별-안내.md | testbed/ai-exam/threats/*) return 0 ;;
        testbed/harness/*/fixtures/* | testbed/harness/*/*/fixtures/*) return 0 ;;
    esac
    for e in "${EXTRA[@]}"; do [ "$f" = "$e" ] && return 0; done
    case "$f" in
        testbed/harness/linux/*/* | testbed/harness/host/*/*) return 1 ;;
        testbed/harness/linux/* | testbed/harness/host/*)
            rule_harness_at "$head" "$f" || rule_harness_at "$base" "$f"
            return
            ;;
    esac
    return 1
}

check() {
    local base=$1 head=$2 f bad=()
    git rev-parse -q --verify "$base^{commit}" >/dev/null || { echo "rule-scope: 바탕 $base 가 이 사본에 없다" >&2; return 2; }
    git rev-parse -q --verify "$head^{commit}" >/dev/null || { echo "rule-scope: 머리 $head 가 이 사본에 없다" >&2; return 2; }
    local files
    files=$(git -c core.quotePath=false diff --no-renames --name-only "$base" "$head")
    if ! grep -q '^plugins/' <<<"$files"; then
        echo "rule-scope: 룰 PR 이 아니다(plugins/ 를 고치지 않았다) — 경로 제한 없음"
        return 0
    fi
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        allowed "$base" "$head" "$f" || bad+=("$f")
    done <<<"$files"
    if [ ${#bad[@]} -gt 0 ]; then
        echo "rule-scope: 룰 PR 이 룰의 자리 밖을 고쳤다 — 도구 · 하네스 바탕 · 엔진 · CI 는 따로 PR 로 낸다:" >&2
        printf '  %s\n' "${bad[@]}" >&2
        return 1
    fi
    echo "rule-scope: 룰 PR — 바뀐 파일 $(grep -c . <<<"$files")개가 모두 룰의 자리 안이다"
}

selftest() {
    local pass=0 bad=0 d
    t() { if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "통과  $1"; else bad=$((bad + 1)); echo "실패  $1 — '$2'(기대 '$3')"; fi; }
    d=$(mktemp -d)
    (
        cd "$d"
        git -c init.defaultBranch=main init -q .
        mkdir -p plugins/a ci docs/changes testbed/harness/linux/fixtures/x testbed/harness/host xtask/src
        printf 'id: a\n' >plugins/a/plugin.yaml
        printf '#!/bin/bash\n# 룰: a — 시험\n' >testbed/harness/linux/a-verify.sh
        printf '#!/bin/bash\n# 필수 점검\n' >testbed/harness/linux/emergency-checks.sh
        printf 'x\n' >ci/batch.sh
        printf 'x\n' >xtask/src/netcriteria.rs
        git add -A && git -c user.email=t@t -c user.name=t commit -qm base
        git tag base
        case_commit() { # 이름 · 파일들(내용은 이름)
            local name=$1
            shift
            git switch -q -c "$name" base
            local f
            for f in "$@"; do mkdir -p "$(dirname "$f")" && printf '%s\n' "$name" >>"$f"; done
            git add -A && git -c user.email=t@t -c user.name=t commit -qm "$name"
        }
        case_commit rule-only plugins/a/plugin.yaml docs/changes/a-0.2.md testbed/harness/linux/a-verify.sh docs/위협별-안내.md
        case_commit rule-and-ci plugins/a/plugin.yaml ci/batch.sh
        case_commit rule-and-gate plugins/a/plugin.yaml testbed/harness/linux/emergency-checks.sh
        case_commit tool-only ci/batch.sh testbed/harness/linux/emergency-checks.sh
        case_commit rule-and-extra plugins/a/plugin.yaml xtask/src/netcriteria.rs testbed/harness/linux/fixtures/x/case.txt
        # 빈 폴더는 git 이 따라가지 않아 가지를 바꾸면 사라진다 — 쓰기 전에 만든다.
        git switch -q -c rule-and-new-harness base
        mkdir -p testbed/harness/host
        printf '#!/bin/bash\n# 룰: b — 새 룰\n' >testbed/harness/host/Invoke-BVerify.ps1
        mkdir -p plugins/b && printf 'id: b\n' >plugins/b/plugin.yaml
        git add -A && git -c user.email=t@t -c user.name=t commit -qm new
        git switch -q -c rule-and-plain-new base
        mkdir -p testbed/harness/host
        printf '#!/bin/bash\n# 도구\n' >testbed/harness/host/New-Tool.ps1
        printf 'id: a2\n' >plugins/a/plugin.yaml
        git add -A && git -c user.email=t@t -c user.name=t commit -qm plain
    ) >/dev/null 2>&1
    r() { (cd "$d" && check base "$1") >/dev/null 2>&1; echo $?; }
    t "룰 · 조각 · 룰 하네스 · 위협별 안내만 — 지난다" "$(r rule-only)" 0
    t "룰 + 출시 스크립트 — 멈춘다" "$(r rule-and-ci)" 1
    t "룰 + 필수 점검(# 룰: 줄 없는 하네스) — 멈춘다" "$(r rule-and-gate)" 1
    t "도구만(룰 PR 이 아니다) — 지난다" "$(r tool-only)" 0
    t "룰 + 조건부 자리 · 하네스 픽스처 — 지난다" "$(r rule-and-extra)" 0
    t "룰 + 새 룰 하네스(# 룰:) — 지난다" "$(r rule-and-new-harness)" 0
    t "룰 + 새 하네스 바탕 스크립트(# 룰: 없음) — 멈춘다" "$(r rule-and-plain-new)" 1
    t "멈출 때 어긋난 파일을 적는다" "$( (cd "$d" && check base rule-and-ci) 2>&1 >/dev/null | grep -c '^  ci/batch.sh$')" 1
    rm -rf "$d"
    echo "--- 통과 $pass · 실패 $bad"
    [ "$bad" = 0 ]
}

case "${1:-}" in
    selftest) selftest ;;
    "") echo "쓰는 법: bash ci/rule-scope.sh <바탕> <머리> | selftest" >&2; exit 2 ;;
    *) check "$1" "${2:?머리}" ;;
esac
