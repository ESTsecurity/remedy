#!/bin/bash
# 배포 본문 — 틀(.github/release-notes.md)을 이 태그의 값으로 채워 stdout 에 쓴다. 배포 워크플로(리눅스 잡 — 도구를 지은
# 뒤 초안의 본문을 바꾼다)와 로컬 미리 보기가 같은 스크립트를 쓴다.
#
#   bash ci/release-notes.sh <태그> [--prev <Latest 의 태그> [--prev-name '<그 Release 이름>']] [--engine <싣는 엔진>]
#                            [--rules <룰 버전>] [--changes <파일>] [--table <파일>]
#
# 저장소 루트에서 — 태그는 v<엔진 버전>[-rc.N] · rules-<룰 버전>[-rc.N]. 값은 배포 잡이 버전 검사의 출력으로 준다:
#   --prev       지금 Latest(주지 않으면 gh 로 그 태그와 이름을 읽는다) — 바뀐 내용의 기준
#   --prev-name  그 Release 의 이름 `프로그램 <엔진> · 룰 <룰>`(주지 않으면 gh 로 읽는다 — 배포 잡은 GH_TOKEN 으로) — 버전
#                줄의 지난 값. git 만으로는 rules 태그가 실은 엔진을 알 수 없다
#   --engine     이 출시가 싣는 엔진(v 태그는 기본 Cargo.toml · rules 태그는 기본 지난 공개본의 엔진 — 룰만 바뀐 출시는
#                Latest 의 엔진을 그대로 싣고, main 의 Cargo.toml 은 앞서 있을 수 있다)
#   --rules      룰 버전(rules 태그는 이름에서 · v 태그는 주석 태그의 메시지에서 — 없으면 이 인자)
#   --changes    바뀐 내용(기본 `cargo xtask changes --since <prev>` — 시험이 파일로 준다)
#   --table      위협 표(기본 `cargo xtask threats --print` — 태그 나무의 매니페스트에서 · 시험이 파일로 준다)
#
# 채우는 것:
#   {{CHANGES}}              이 태그가 지금 Latest 뒤에 새로 실은 업데이트 내역 조각(docs/changes/)을 모은 칸의 짧은 꼴 —
#                            첫 화면은 칸마다 꼭대기 항목의 제목 줄, 그 아래 알아두실 점 접기와 자세한 내용 접기(그 밖의
#                            원문 그대로). 어느 접기를 옮겨 어느 항목의 제목 아래 두는지는 아래 '바뀐 내용의 짧은 꼴(brief)'
#                            블록에만 적는다.
#                            조각이 없으면 멈춘다(바뀐 내용이 빠진 본문을 올리지 않는다).
#                            2026-11-21 부터 — 전에는 업데이트 내역 파일의 칸 · 2026-11-28 부터 짧은 꼴 — 전에는 원문 그대로라
#                            v1.27.0 의 2절이 본문의 66% 였다
#   {{SINCE}}                (프로그램 <칸> · 룰 <칸>) — 칸마다 지난 공개본의 값과 같으면 `<값> 그대로`, 다르면 `<지난 값> →
#                            <이번 값>`(예: `(프로그램 1.26.0 → 1.27.0 · 룰 2026.11.27 그대로)`). 차례는 Release 이름과 같다.
#                            2026-11-28 부터 — 전에는 태그 종류마다 한 칸(`룰 X` → `프로그램 Y`)이라 종류가 다른 두 출시 사이에서
#                            서로 다른 것을 견줬다
#   {{TABLE}}                위협 표를 본문의 꼴로 — 정렬 표시와 '하는 일' 칸을 '방식' 칸으로(머리 · 값). Windows · Linux 칸의
#                            차례가 다르거나 모르는 '하는 일' 문구면 멈춘다(아래 job_ko — 그 문구는 xtask/src/threats.rs 가 짓는다)
#   {{SUMMARY}}              그 표의 줄마다 룰 매니페스트로 가른 묶음 — 악성코드 치료(remediate) · 악성코드 검사(그 밖) ·
#                            취약한 버전 · 설정 검사(kind: check) · 네트워크 기반 점검(network). 묶음 안에서는 OS 로 다시 묶는다
#   {{REPO_URL}} · {{HISTORY_URL}}(릴리스 목록 — 업데이트 내역 파일은 하루 한 번 갈아 끼워 하루 늦을 수 있다)
#
# 다 채운 뒤 채우지 못한 자리 · 닫히지 않은 코드 블록 · 짝이 맞지 않는 <details> · 상대 링크가 있으면 멈춘다 — 2026-11-18
# 에 손으로 다듬은 본문이 확인 명령 중간에서 끊긴 채 공개된 일이 있었다. 조각의 꼴은 PR 에서 `cargo xtask fragments` 가
# 먼저 본다. 이 스크립트 · 틀을 고치면 `bash ci/release-notes-test.sh` — 두 종류의 본문과 멈춤 장치를 저장소 밖 사본에서
# 본다(PR 의 CI 도 돌린다).
set -euo pipefail
# 로캘을 배포 잡(ubuntu · C.UTF-8)과 같게 맞춘다 — 로캘이 비어 있는 Git Bash 에서는 [[:space:]] 가 바이트 0xA0 을 공백으로
# 봐, 아래 trim 이 '참고' 의 '고'(EA B3 A0)처럼 그 바이트로 끝나는 글자를 잘랐다(2026-11-20 미리 보기). 태그 전 미리 보기가
# 배포 잡과 같은 본문을 내야 한다.
export LC_ALL=C.UTF-8

tag="" prev="" prev_name="" engine="" rules="" changes_file="" table_file=""
while [ $# -gt 0 ]; do
    case "$1" in
        --prev) prev=$2; shift 2 ;;
        --prev-name) prev_name=$2; shift 2 ;;
        --engine) engine=$2; shift 2 ;;
        --rules) rules=$2; shift 2 ;;
        --changes) changes_file=$2; shift 2 ;;
        --table) table_file=$2; shift 2 ;;
        -*) echo "모르는 인자: $1" >&2; exit 2 ;;
        *) [ -z "$tag" ] || { echo "태그는 하나만: $1" >&2; exit 2; }; tag=$1; shift ;;
    esac
done
[ -n "$tag" ] || { echo "쓰는 법: bash ci/release-notes.sh <태그> [--prev <태그> [--prev-name <이름>]] [--engine <X.Y.Z>] [--rules <룰 버전>]" >&2; exit 2; }
tpl=.github/release-notes.md
for f in "$tpl" Cargo.toml; do
    [ -f "$f" ] || { echo "::error::$f 가 없다 — 저장소 루트에서 부를 것" >&2; exit 2; }
done
repo=${GITHUB_REPOSITORY:-ESTsecurity/remedy}

# Release 이름 · 주석 태그 메시지 '프로그램 <엔진> · 룰 <룰>' 의 칸 하나(1 = 엔진 · 2 = 룰) — 그 꼴이 아니면 빈 값.
name_part() { sed -nE "s/^프로그램 ([0-9]+\\.[0-9]+\\.[0-9]+) · 룰 ([0-9.]+)\$/\\$2/p" <<<"$1"; }

case "$tag" in
    rules-*)
        name=${tag#rules-}
        name=${name%-rc.*}
        [ -z "$rules" ] || [ "$rules" = "$name" ] || { echo "::error::--rules $rules 이 태그 $tag 와 다르다" >&2; exit 2; }
        rules=$name
        ;;
    v*)
        [ -n "$engine" ] || engine=$(grep -m1 -E '^\s*version' Cargo.toml | cut -d'"' -f2)
        if [ -z "$rules" ]; then
            subject=$(git for-each-ref --format='%(contents:subject)' "refs/tags/$tag" 2>/dev/null || true)
            rules=$(name_part "$subject" 2)
        fi
        [ -n "$rules" ] || { echo "::error::v 태그 $tag 의 룰 버전이 없다 — 주석 태그의 메시지 첫 줄이나 --rules" >&2; exit 2; }
        ;;
    *) echo "::error::태그 $tag 는 v<엔진 버전> 도 rules-<룰 버전> 도 아니다" >&2; exit 2 ;;
esac
if [ -z "$prev" ]; then
    got=$(gh release view --repo "$repo" --json tagName,name --jq '.tagName + "\t" + .name' 2>/dev/null) ||
        { echo "::error::지금 Latest 를 읽지 못했다 — gh 로그인 · GH_TOKEN 을 보거나 --prev · --prev-name 을 준다" >&2; exit 2; }
    prev=${got%%$'\t'*}
    prev_name=${got#*$'\t'}
elif [ -z "$prev_name" ]; then
    prev_name=$(gh release view "$prev" --repo "$repo" --json name --jq .name 2>/dev/null) ||
        { echo "::error::지난 공개본 $prev 의 Release 이름을 읽지 못했다 — gh 로그인 · GH_TOKEN 을 보거나 --prev-name 을 준다" >&2; exit 2; }
fi
# 버전 줄의 지난 값 — 그 Release 의 이름에서(version-check.sh 가 견준 것과 같은 Release).
prev_engine=$(name_part "$prev_name" 1)
prev_rules=$(name_part "$prev_name" 2)
if [ -z "$prev_engine" ] || [ -z "$prev_rules" ]; then
    echo "::error::지난 공개본 $prev 의 이름 '$prev_name' 이 '프로그램 <엔진> · 룰 <룰>' 꼴이 아니다" >&2
    exit 2
fi
case "$prev" in
    "v$prev_engine" | "rules-$prev_rules") ;;
    *) echo "::error::지난 공개본 $prev 와 그 이름의 버전이 다르다('$prev_name')" >&2; exit 2 ;;
esac
[ -n "$engine" ] || engine=$prev_engine

# ── 바뀐 내용의 짧은 꼴(brief) ──────────────────────────────────────────────────────────────────────
# ### 칸마다 첫 화면에는 꼭대기 항목(들여 쓰지 않은 · <details> 밖 · 코드 블록 밖의 '* ' 줄)의 제목 줄만 끝의 \ 하나를 떼고
# 두고, 그 아래에 접기를 둘까지 이 차례로 둔다(2026-11-28). 이 규칙은 여기에만 적는다 — 스크립트 머리 · 조각 안내 · 개발
# 안내 · 틀 머리는 이 블록을 가리킨다. 이 블록의 낱말:
#   꼭대기 접기       <details> 밖 · 코드 블록 밖에서 여는 접기.
#   정한 꼴           꼭대기 접기 가운데 들이지 않은 여는 줄이 `<details>` 와 NOTE_SUMMARY(조각 안내의 꼴) 두 줄이거나 그 둘을
#                     이은 한 줄로, 바이트까지 같은 것(끝에 공백이 붙어도 아니다 — 아래 note_open).
#   빈 줄             길이 0 인 줄. 공백뿐인 줄은 빈 줄이 아니라 들인 글 줄이다.
#   알아두실 점       정한 꼴의 접기 가운데 그 접기만 닫는 줄(앞뒤 공백만 둔 `</details>` · 아래 note_closes_alone)로 닫히고,
#                     안쪽이 비지 않은 것을 원문 차례대로 옮긴다. 닫는 줄을 찾다가 지금 깊이만큼의 `</details>` 와 그 뒤의
#                     `<details>` 를 함께 담은 줄(한 줄에서 닫고 다시 여는 줄 · 글이나 인라인 코드 안이라도)을 만나면 닫히는지
#                     가리지 못해 옮기지 않는다. 덩이 사이는 빈 줄이다. 어디에 두나(아래 note_add):
#                     - 옮긴 접기 바로 뒤(사이에 빈 줄뿐)면 그 사이에 항목이 없어도 옮기고, 앞 덩이에 빈 줄 하나를 두고 같은
#                       들여쓰기로 잇는다.
#                     - 아니면 칸의 처음 · 앞의 정한 꼴 접기(옮겼든 말든) · 세는 구간을 끊는 줄 가운데 마지막 것 뒤로 이 접기
#                       앞의 꼭대기 항목을 센다. 하나면 그 제목 줄 아래 두 칸 들이고, 여럿이면 제목 없이 원문 그대로, 없으면
#                       옮기지 않는다(자세한 내용 접기에 원문 그대로).
#                     - 세는 구간을 끊는 줄(아래 list_ends)은 <details> 밖 · 코드 블록 밖에서 들이지 않은 글 줄 가운데 '* '
#                       항목 줄도 접기 줄(`<details>` · `</details>` 를 담은 줄)도 아닌 것 — 문단 · 코드 블록을 여는 줄 ·
#                       '- ' 목록 줄 등이다. 앞에 공백 · 탭이 하나라도 있는 줄 · 접기 줄 · 접기 안이나 코드 블록 안의 줄은
#                       끊지 않는다.
#                     - 같은 칸에 조각이 여럿 들면 앞 조각의 항목도 센다 — 조각의 경계는 이 본문에 없다.
#                     고객이 할 일이 긴 설명 뒤로 밀리지 않게 한다(v1.27.0 은 한 접기 안에서 설명 뒤였다).
#   자세한 내용 보기  칸의 원문에서 위로 옮긴 접기(여는 줄 · summary · 안쪽 · 닫는 줄)만 뺀 나머지 그대로 — 제목 줄 · 줄 끝의 \ ·
#                     하위 줄 · 다른 꼴의 접기 · 펴지 못한 접기도. 남는 것이 제목 줄과 빈 줄뿐이면 두지 않는다.
# 낱말로 골라 올리거나 문장을 자르지 않는다 — 첫 화면에 둘 것은 조각을 쓰는 사람이 꼭대기 항목으로 적는다
# (docs/changes/README.md). 조각의 꼴과 업데이트 내역 파일은 그대로다(cargo xtask changes · views 는 원문을 낸다).
NOTE_SUMMARY='<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>'

# $1 안에 $2 가 든 수 — REPLY 에(줄마다 부르므로 하위 셸을 띄우지 않는다).
count_of() {
    local t=${1//"$2"/}
    REPLY=$(((${#1} - ${#t}) / ${#2}))
}

# 정한 꼴의 접기가 칸의 $1 번째 줄(여는 줄 다음)부터 그 접기만 닫는 줄 — 앞뒤 공백만 둔 `</details>` — 로 닫히는가(옮겨도
# 되는가 · 닫는 줄의 차례는 REPLY 에). 깊이와 코드 블록은 brief_keep 과 같게 센다. 같은 줄에서 글과 함께 닫거나 닫히지 않으면
# 1 — 그 접기는 옮기지 않고 원문 그대로 둔다. 닫는 줄을 알아보지 못한 채 옮기면 짝이 어긋나고, 그 멈춤은 태그를 민 뒤의 본문
# 짓기에서야 드러난다(2026-11-28 반박 검토에서 찾았다 — PR 의 `cargo xtask fragments` 는 개수만 센다). 칸의 줄은
# brief_section 의 body 다. 깊이는 줄 끝의 순 증감이라 한 줄에서 닫고 다시 여는 줄(`</details><details>`)을 지나쳐 다음 접기의
# 닫는 줄을 이 접기의 것으로 보고 다른 접기까지 옮겼다(2026-11-28 다시 보기) — 그 줄에서 닫힐 수 있고(`</details>` 가 지금
# 깊이만큼 있다) 그 뒤에 `<details>` 를 함께 담으면 1. 닫히는지 가리지 못하는 줄(`<details>a</details><details>`)도 1 이다 —
# 옮기지 않는 쪽은 짝이 어긋나지 않는다.
note_closes_alone() {
    local k l depth=1 fence=0
    for ((k = $1; k < ${#body[@]}; k++)); do
        l=${body[k]}
        if [ "$fence" = 0 ]; then
            count_of "$l" '</details>'
            [ "$REPLY" -lt "$depth" ] || [[ $l != *'</details>'*'<details>'* ]] || return 1
            depth=$((depth - REPLY))
            count_of "$l" '<details>'
            depth=$((depth + REPLY))
            if [ "$depth" -le 0 ]; then
                REPLY=$k
                [[ $l =~ ^[[:space:]]*'</details>'[[:space:]]*$ ]]
                return
            fi
        fi
        [[ ! $l =~ ^[[:space:]]*\`\`\` ]] || fence=$((1 - fence))
    done
    return 1
}

# 칸의 꼭대기 줄 body[$1] 이 정한 꼴의 알아두실 점 접기를 여는가(여는 줄이 <details> · <summary> 두 줄이거나 한 줄) — 열면
# 안쪽 첫 줄의 차례를 REPLY 에.
note_open() {
    if [ "${body[$1]}" = '<details>' ] && [ "${body[$1+1]-}" = "$NOTE_SUMMARY" ]; then
        REPLY=$(($1 + 2))
    elif [ "${body[$1]}" = "<details>$NOTE_SUMMARY" ]; then
        REPLY=$(($1 + 1))
    else
        return 1
    fi
}

# 칸의 꼭대기 줄 body[$1] 이 옮길 수 있는 알아두실 점 접기를 여는가 — 정한 꼴이고 · 그 접기만 닫는 줄로 닫히고 · note_add 가
# 받으면 알아두실 점 접기에 더하고 REPLY 에 닫는 줄의 차례를 둔다. 아니면 1 — 그 줄은 자세한 내용 접기에 원문 그대로 남는다.
# 정한 꼴의 접기는 옮기든 말든 항목을 세는 구간(b_n)을 끝낸다.
brief_note() {
    local from end n=$b_n
    note_open "$1" || return 1
    from=$REPLY
    b_n=0
    note_closes_alone "$from" || return 1
    end=$REPLY
    note_add "$from" "$end" "$n" || return 1
    REPLY=$end
}

# 알아두실 점 접기의 한 덩이 — body[$1] ~ body[$2 - 1](앞뒤의 빈 줄은 뗀다). 어디에 두는지는 위 '바뀐 내용의 짧은 꼴(brief)'
# 블록의 '알아두실 점'.
# $3 은 세는 구간에서 이 접기 앞의 꼭대기 항목 수다. 옮긴 접기 바로 뒤(b_cont)면 $3 을 보지 않고 빈 줄 하나를 두고 잇는다 — 빈 줄
# 없이 이으면 두 접기의 문단이 한 문단으로 붙고, 제목 없는 덩이에서는 뒤 문단이 앞 항목의 줄이 된다(2026-11-28 다시 보기).
# 항목이 둘 이상이면 어느 항목의 것인지 몰라 제목 없이 둔다 — 공개한 엔진 조각은 항목 여럿 뒤에 접기 하나라, 마지막 항목의 제목
# 아래 두면 v1.27.0 의 '꺼낸 폴더의 사본' 경고가 관계없는 항목에 딸렸다(2026-11-28 검토). 잇지 않는데 항목이 없거나, 안쪽이
# 비었으면 1.
note_add() {
    local k=$1 e=$2
    while [ "$k" -lt "$e" ] && [ -z "${body[k]}" ]; do k=$((k + 1)); done
    while [ "$e" -gt "$k" ] && [ -z "${body[e-1]}" ]; do e=$((e - 1)); done
    [ "$k" -lt "$e" ] || return 1
    if [ "$b_cont" = 1 ]; then b_notes+=(''); else note_head "$3" || return 1; fi
    for (( ; k < e; k++)); do
        if [ -n "${body[k]}" ]; then b_notes+=("$b_ind${body[k]}"); else b_notes+=(''); fi
    done
    b_cont=1
}

# 새 덩이의 머리 — 앞 덩이와 빈 줄로 띄우고, 꼭대기 항목 수 $1 이 하나면 그 제목 줄과 두 칸 들여쓰기(b_ind). 없으면 1.
note_head() {
    [ "$1" -gt 0 ] || return 1
    [ ${#b_notes[@]} = 0 ] || b_notes+=('')
    b_ind=''
    if [ "$1" = 1 ]; then b_notes+=("$b_top") b_ind='  '; fi
}

# 꼭대기에서 목록을 끝내는 글 줄인가 — 접기 밖 · 코드 밖에서 들이지 않았고 접기 줄이 아니다(문단 · 코드 블록을 여는 줄이
# 그렇다 — 빈 줄 · 항목 줄은 부르는 쪽이 먼저 거른다). 그 뒤의 알아두실 점 접기는 앞 항목에 딸리지 않는다 — 같은 칸의 앞
# 조각이 끝난 자리일 수 있다.
list_ends() {
    [ "$b_fence" = 0 ] && [ "$b_depth" = 0 ] && [[ $1 != [[:space:]]* && $1 != *'<details>'* && $1 != *'</details>'* ]]
}

# 칸의 그 밖의 줄 — 자세한 내용 접기에 원문 그대로 둔다. <details> 깊이와 코드 블록을 따라가며, 꼭대기 항목의 제목 줄(끝의 \ 는
# 뗀다)은 첫 화면에도 두고 뒤의 알아두실 점이 딸릴 항목(b_top)으로 삼아 센다(b_n). 제목 아닌 글이 한 줄이라도 있으면 b_other ·
# 빈 줄이 아닌 줄은 앞의 옮긴 접기와 잇기를 끊는다(b_cont).
brief_keep() {
    local line=$1
    if [ "$b_fence" = 0 ] && [ "$b_depth" = 0 ] && [[ $line == '* '* ]]; then
        b_top=${line%\\}
        b_titles+=("$b_top")
        b_n=$((b_n + 1))
    elif [ -n "$line" ]; then
        b_other=1
        if list_ends "$line"; then b_n=0; fi
    fi
    [ -z "$line" ] || b_cont=0
    if [ "$b_fence" = 0 ]; then
        count_of "$line" '<details>'
        b_depth=$((b_depth + REPLY))
        count_of "$line" '</details>'
        b_depth=$((b_depth - REPLY))
    fi
    [[ ! $line =~ ^[[:space:]]*\`\`\` ]] || b_fence=$((1 - b_fence))
    b_fold+=("$line")
}

# 접기 하나 — 이름 · 안쪽 줄들. 앞에 낸 줄(제목 · 앞 접기)이 있으면 빈 줄 하나를 사이에 둔다(b_gap).
brief_fold() {
    [ "$b_gap" = 0 ] || printf '\n'
    b_gap=1
    printf '%s\n' '<details>' "<summary><b>$1</b></summary>" ''
    shift
    printf '%s\n' "$@" '' '</details>'
}

# 칸 하나를 낸다 — 머리 · 빈 줄 · 제목 줄들 · (있으면) 알아두실 점 접기 · (제목 아닌 글이 있으면) 자세한 내용 접기.
brief_print() {
    while [ ${#b_fold[@]} -gt 0 ] && [ -z "${b_fold[${#b_fold[@]}-1]}" ]; do unset 'b_fold[${#b_fold[@]}-1]'; done
    printf '%s\n' "$1" ''
    b_gap=0
    if [ ${#b_titles[@]} -gt 0 ]; then
        printf '%s\n' "${b_titles[@]}"
        b_gap=1
    fi
    [ ${#b_notes[@]} = 0 ] || brief_fold '알아두실 점' "${b_notes[@]}"
    [ "$b_other" = 0 ] || brief_fold '자세한 내용 보기' "${b_fold[@]}"
}

# 칸 하나 — 머리 줄 · 그 칸의 줄들. 상태는 b_* 에 칸마다 새로 둔다. 옮긴 접기 뒤의 빈 줄이 앞의 빈 줄과 겹치면 하나만(b_skip).
brief_section() {
    local head=$1 line j
    shift
    local -a body=("$@")
    b_titles=() b_notes=() b_fold=()
    b_depth=0 b_fence=0 b_other=0 b_skip=0 b_top='' b_n=0 b_cont=0 b_ind=''
    for ((j = 0; j < ${#body[@]}; j++)); do
        line=${body[j]}
        # 앞의 빈 줄은 뗀다(뒤의 빈 줄은 brief_print 가).
        if [ ${#b_fold[@]} = 0 ] && [ -z "$line" ]; then continue; fi
        if [ "$b_skip" = 1 ]; then
            b_skip=0
            if [ -z "$line" ] && [ -z "${b_fold[${#b_fold[@]}-1]}" ]; then continue; fi
        fi
        if [ "$b_fence" = 0 ] && [ "$b_depth" = 0 ] && brief_note "$j"; then
            j=$REPLY b_skip=1
            continue
        fi
        brief_keep "$line"
    done
    brief_print "$head"
}

# 바뀐 내용 전체 — 첫 ### 앞의 줄은 그대로 옮기고(모으는 쪽은 늘 ### 로 연다), 칸 사이는 빈 줄 하나. 칸의 차례와 이름은
# cargo xtask changes 가 정한 그대로다.
brief() {
    local -a lines=()
    local line i=0 s n first=1
    while IFS= read -r line || [ -n "$line" ]; do lines+=("$line"); done
    n=${#lines[@]}
    while [ "$i" -lt "$n" ] && [[ ${lines[i]} != '### '* ]]; do printf '%s\n' "${lines[i]}"; i=$((i + 1)); done
    while [ "$i" -lt "$n" ]; do
        s=$((i + 1))
        i=$s
        while [ "$i" -lt "$n" ] && [[ ${lines[i]} != '### '* ]]; do i=$((i + 1)); done
        [ "$first" = 1 ] || printf '\n'
        first=0
        brief_section "${lines[s-1]}" "${lines[@]:s:i-s}"
    done
}

# ── 바뀐 내용 — Latest 뒤에 새로 든 조각 ─────────────────────────────────────────────────────────────
if [ -n "$changes_file" ]; then
    changes=$(tr -d '\r' <"$changes_file" | sed '/./,$!d')
else
    changes=$(cargo xtask changes --since "$prev" 2>/dev/null | tr -d '\r' | sed '/./,$!d') || changes=""
fi
if [ -z "$changes" ]; then
    echo "::error::$prev 뒤에 더한 업데이트 내역 조각이 없다 — 이 출시에서 바뀐 것을 docs/changes/ 에 먼저 적는다(cargo xtask changes --since $prev)" >&2
    exit 1
fi
changes=$(brief <<<"$changes")
# 머리의 칸 하나 — 지난 공개본의 값과 같으면 '<값> 그대로', 다르면 '<지난 값> → <이번 값>'. 차례는 Release 이름과 같다.
pair() { if [ "$2" = "$3" ]; then printf '%s %s 그대로' "$1" "$3"; else printf '%s %s → %s' "$1" "$2" "$3"; fi; }
since="($(pair 프로그램 "$prev_engine" "$engine") · $(pair 룰 "$prev_rules" "$rules"))"

# ── 위협 표와 묶음 — 태그 나무의 매니페스트 ──────────────────────────────────────────────────────────
if [ -n "$table_file" ]; then
    table_src=$(tr -d '\r' <"$table_file")
else
    table_src=$(cargo xtask threats --print 2>/dev/null | tr -d '\r') || table_src=""
fi
rows=$(sed '/^[[:space:]]*$/d' <<<"$table_src")
if [ -z "$rows" ]; then
    echo "::error::위협 표를 짓지 못했다 — cargo xtask threats --print" >&2
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
repo_url="${GITHUB_SERVER_URL:-https://github.com}/$repo"
# 지난 버전의 변경 내용 — 릴리스 목록(늘 최신이다). 업데이트 내역 파일은 하루 한 번 갈아 끼워 하루 늦을 수 있다.
history_url="$repo_url/releases"
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
