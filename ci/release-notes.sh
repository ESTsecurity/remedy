#!/bin/bash
# 배포 본문 — 틀(.github/release-notes.md)을 이 태그의 값으로 채워 stdout 에 쓴다. 배포 워크플로의 초안(`draft` 잡)과
# 로컬 미리 보기가 같은 스크립트를 쓴다.
#
#   bash ci/release-notes.sh <태그>      저장소 루트에서 — 태그는 v<엔진 버전>[-rc.N] · rules-<룰 버전>[-rc.N]
#
# 채우는 것:
#   {{CHANGES}}              docs/업데이트-내역.md 의 이 버전 칸 — 없으면 멈춘다(바뀐 내용이 빠진 본문을 올리지 않는다).
#                            칸의 이름은 머리의 앞 낱말이다 — 엔진이 바뀐 출시는 `<엔진 버전>`, 룰만 바뀐 출시는 `룰 <룰 버전>`
#   {{SINCE}}                (`<지난 칸>` → `<이 칸>`) — 지난 칸은 그 파일에서 바로 아래 칸
#   {{TABLE}}                README 의 위협 표(`cargo xtask threats` 가 룰과 같은지 매 커밋 본다)를 본문의 꼴로 — 정렬 표시와
#                            '하는 일' 칸을 '방식' 칸으로(머리 · 값). Windows · Linux 칸의 차례가 다르거나 모르는 '하는 일'
#                            문구면 멈춘다(아래 job_ko — 그 문구는 xtask/src/threats.rs 가 짓는다)
#   {{SUMMARY}}              그 표의 줄마다 룰 매니페스트로 가른 묶음 — 악성코드 치료(remediate) · 악성코드 검사(그 밖) ·
#                            취약한 버전 · 설정 검사(kind: check) · 네트워크 기반 점검(network). 묶음 안에서는 OS 로 다시 묶는다
#   {{REPO_URL}} · {{HISTORY_URL}}
#
# 다 채운 뒤 채우지 못한 자리 · 닫히지 않은 코드 블록 · 짝이 맞지 않는 <details> · 상대 링크가 있으면 멈춘다 — 2026-11-18
# 에 손으로 다듬은 본문이 확인 명령 중간에서 끊긴 채 공개된 일이 있었다. 긴급 경로는 rc 없이 정식 태그에서 처음 돌므로
# 태그를 밀기 전에 미리 본다(docs/긴급-대응.md).
set -euo pipefail
# 로캘을 배포 잡(ubuntu · C.UTF-8)과 같게 맞춘다 — 로캘이 비어 있는 Git Bash 에서는 [[:space:]] 가 바이트 0xA0 을 공백으로
# 봐, 아래 trim 이 '참고' 의 '고'(EA B3 A0)처럼 그 바이트로 끝나는 글자를 잘랐다(2026-11-20 미리 보기). 태그 전 미리 보기가
# 배포 잡과 같은 본문을 내야 한다.
export LC_ALL=C.UTF-8

tag=${1:-}
[ -n "$tag" ] || { echo "쓰는 법: bash ci/release-notes.sh <태그>" >&2; exit 2; }
tpl=.github/release-notes.md
log=docs/업데이트-내역.md
for f in "$tpl" "$log" README.md Cargo.toml plugins/RULES-VERSION; do
    [ -f "$f" ] || { echo "::error::$f 가 없다 — 저장소 루트에서 부를 것" >&2; exit 2; }
done

engine=$(grep -m1 -E '^\s*version' Cargo.toml | cut -d'"' -f2)
rules=$(tr -d '\r\n' <plugins/RULES-VERSION)
case "$tag" in
    rules-*) key="룰 $rules" ;;
    v*) key=$engine ;;
    *) echo "::error::태그 $tag 는 v<엔진 버전> 도 rules-<룰 버전> 도 아니다" >&2; exit 2 ;;
esac

# ── 바뀐 내용 — 업데이트 내역의 이 버전 칸 ─────────────────────────────────────────────────────────
head="## $key"
changes=$(awk -v h="$head" 'f && /^## / { exit } f { print } index($0, h " ") == 1 || $0 == h { f = 1 }' "$log" |
    tr -d '\r' | sed '/./,$!d')
prev=$(awk -v h="$head" 'f && /^## / { print ($2 == "룰" ? $2 " " $3 : $2); exit } index($0, h " ") == 1 || $0 == h { f = 1 }' "$log")
if [ -z "$changes" ]; then
    echo "::error::$log 에 '$head' 칸이 없다 — 이 버전에서 바뀐 내용을 먼저 적는다" >&2
    exit 1
fi
# 제목의 두 칸에 같은 꼴의 이름을 붙인다 — 엔진 출시의 칸 이름은 버전 숫자뿐이라 '룰 2026.11.18.2 → 1.24.0' 처럼 짝이
# 맞지 않았다(2026-11-18 검토).
label() { case "$1" in '룰 '*) printf '%s' "$1" ;; *) printf '프로그램 %s' "$1" ;; esac; }
if [ -n "$prev" ]; then
    since="(\`$(label "$prev")\` → \`$(label "$key")\`)"
else
    since="(\`$(label "$key")\`)"
fi

# ── 위협 표와 묶음 — README 의 표 · 룰 매니페스트 ────────────────────────────────────────────────────
rows=$(sed -n '/<!-- threats:begin/,/<!-- threats:end -->/p' README.md | sed '1d;$d' | tr -d '\r')
if [ -z "$rows" ]; then
    echo "::error::README 에 위협 표가 없다 — cargo xtask threats --write" >&2
    exit 1
fi

# README 의 '하는 일'(합쇼체 문장 · xtask threats 가 짓는다) → 본문 표의 '방식'(이름 · 이슈 #120).
job_ko() {
    case "$1" in
        '찾기만 합니다') printf '%s' '검사' ;;
        '찾아서 치료합니다 (복원할 수 있습니다)') printf '%s' '악성코드 치료' ;;
        '적어 주신 주소의 서버를 바깥에서 봅니다 (네트워크 사용)') printf '%s' '웹서버 주소 대상 네트워크 기반 점검' ;;
        *) return 1 ;;
    esac
}
trim() {
    local s=$1
    s=${s#"${s%%[![:space:]]*}"}
    s=${s%"${s##*[![:space:]]}"}
    printf '%s' "$s"
}

declare -A items=()
table=""
n=0
while IFS= read -r line; do
    n=$((n + 1))
    if [ "$n" = 1 ]; then
        # 칸은 자리로 읽는다(아래 read · OS 묶음) — 셋째 · 넷째 칸이 Windows · Linux 가 아니면 묶음을 엉뚱한 OS 로 짓지
        # 않고 멈춘다. 둘째 칸('하는 일')은 머리를 '방식' 으로 바꿔 쓰고 값은 job_ko 가 본다. 그 밖의 칸 이름은 그대로 옮긴다.
        IFS='|' read -r _ h_name _ h_win h_lin h_ref _ <<<"$line"
        if [ "$(trim "$h_win")" != Windows ] || [ "$(trim "$h_lin")" != Linux ]; then
            echo "::error::README 위협 표의 머리가 '$line' 이다 — ci/release-notes.sh 는 셋째 · 넷째 칸을 Windows · Linux 로 읽는다" >&2
            exit 1
        fi
        table+="| $(trim "$h_name") | 방식 | Windows | Linux | $(trim "$h_ref") |"$'\n'
        continue
    fi
    if [ "$n" = 2 ]; then table+='| :--- | :--- | :--- | :--- | :--- |'$'\n'; continue; fi
    IFS='|' read -r _ name job win lin ref _ <<<"$line"
    name=$(trim "$name")
    job=$(trim "$job")
    win=$(trim "$win")
    lin=$(trim "$lin")
    ref=$(trim "$ref")
    if ! job2=$(job_ko "$job"); then
        echo "::error::README 위협 표의 '하는 일' 이 모르는 문구다: '$job' — ci/release-notes.sh 의 job_ko 에 본문 표의 '방식' 이름을 더한다" >&2
        exit 1
    fi
    table+="| $name | $job2 | $win | $lin | $ref |"$'\n'
    # 그 줄의 룰 — 두 OS 칸 가운데 먼저 적힌 것. 두 OS 의 룰은 하는 일이 같다.
    id=$(printf '%s %s' "$win" "$lin" | sed -n 's/^[^`]*`\([^`]*\)`.*/\1/p')
    y="plugins/$id/plugin.yaml"
    if [ -z "$id" ] || [ ! -f "$y" ]; then
        echo "::error::위협 표 '$name' 줄의 룰 매니페스트가 없다: $y" >&2
        exit 1
    fi
    if grep -q '^network:' "$y"; then c=4
    elif grep -q '^remediate:' "$y"; then c=1
    elif grep -qE '^kind:[[:space:]]*check' "$y"; then c=3
    else c=2
    fi
    if [ "$win" != "—" ] && [ "$lin" != "—" ]; then os='Windows · Linux'
    elif [ "$win" != "—" ]; then os=Windows
    else os=Linux
    fi
    k="$c|$os"
    items["$k"]="${items["$k"]:+${items["$k"]} · }$name"
done <<<"$rows"
table=${table%$'\n'}

titles=(
    ''
    '**악성코드 치료 항목** (치료하기 전 원본을 보관해서 복원 가능)'
    '**악성코드 검사 항목** (치료가 아닌 탐지만 진행)'
    '**취약한 버전 · 설정 검사** (취약한 버전 · 설정 탐지만 진행)'
    '**웹서버 주소 대상 네트워크 기반 점검** (네트워크 사용)'
)
summary=""
for c in 1 2 3 4; do
    shown=
    for os in 'Windows · Linux' Windows Linux; do
        k="$c|$os"
        [ -n "${items["$k"]:-}" ] || continue
        if [ -z "$shown" ]; then summary+="* ${titles[$c]}"$'\n'; shown=1; fi
        summary+="  * **$os:** ${items["$k"]}"$'\n'
    done
done
summary=${summary%$'\n'}

# ── 틀 채우기 ────────────────────────────────────────────────────────────────────────────────────
repo_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-ESTsecurity/remedy}"
history_url="$repo_url/blob/main/docs/%EC%97%85%EB%8D%B0%EC%9D%B4%ED%8A%B8-%EB%82%B4%EC%97%AD.md"
out=""
first=1
skip=0
while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    # 틀 머리의 안내 덩어리(<!-- … -->)는 본문에 넣지 않는다.
    if [ "$first" = 1 ]; then
        first=0
        [[ "$line" == '<!--'* ]] && skip=1
    fi
    if [ "$skip" = 1 ]; then
        [[ "$line" == *'-->'* ]] && skip=0
        continue
    fi
    case "$line" in
        '{{CHANGES}}') out+="$changes"$'\n'; continue ;;
        '{{SUMMARY}}') out+="$summary"$'\n'; continue ;;
        '{{TABLE}}') out+="$table"$'\n'; continue ;;
    esac
    line=${line//'{{SINCE}}'/"$since"}
    line=${line//'{{REPO_URL}}'/"$repo_url"}
    line=${line//'{{HISTORY_URL}}'/"$history_url"}
    out+="$line"$'\n'
done <"$tpl"

# ── 꼴 확인 ─────────────────────────────────────────────────────────────────────────────────────
left=$(grep -o '{{[A-Z_]*}}' <<<"$out" | sort -u | tr '\n' ' ' || true)
if [ -n "$left" ]; then
    echo "::error::채우지 못한 자리가 남았다: $left" >&2
    exit 1
fi
fences=$(grep -c '^[[:space:]]*```' <<<"$out" || true)
if [ $((fences % 2)) != 0 ]; then
    echo "::error::닫히지 않은 코드 블록이 있다(\`\`\` 줄 $fences 개)" >&2
    exit 1
fi
open=$(grep -c '<details>' <<<"$out" || true)
close=$(grep -c '</details>' <<<"$out" || true)
if [ "$open" != "$close" ]; then
    echo "::error::<details> $open 개 · </details> $close 개 — 짝이 맞지 않는다" >&2
    exit 1
fi
# 릴리스 본문에서는 상대 링크가 열리지 않는다 — 2026-11-18 의 본문 하나를 공개 전에 손으로 절대 주소로 고쳤다.
rel=$(grep -oE '\]\([^)]*\)' <<<"$out" | grep -vE '^\]\((https?://|#)' | sort -u | tr '\n' ' ' || true)
if [ -n "$rel" ]; then
    echo "::error::상대 링크는 릴리스 본문에서 열리지 않는다: $rel — https:// 절대 주소로 적는다" >&2
    exit 1
fi
printf '%s' "$out"
