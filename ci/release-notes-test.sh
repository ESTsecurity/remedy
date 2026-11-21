#!/bin/bash
# ci/release-notes.sh 의 시험 — 저장소 밖 임시 폴더에 그 스크립트가 읽는 파일을 옮겨, 두 종류(룰만 · 엔진)의 본문이 지어지는지와
# 멈춤 장치마다 멈추는지 본다.
#
#   bash ci/release-notes-test.sh      (저장소 루트에서)
#
# 위협 표는 지금 README 의 표(`cargo xtask threats` 가 짓는 꼴 — 표 머리 · '하는 일' 문구가 스크립트의 칸 읽기 · `job_ko` 와
# 어긋나면 여기서 깨진다)를 `--table` 로 주고, 바뀐 내용은 두 종류의 칸 본문을 `--changes` 로 준다(배포 잡은 둘을
# `cargo xtask threats --print` · `cargo xtask changes` 로 짓는다). 버전은 가짜 값(룰 2099.01.01 · 엔진 9.9.9)이고 지금
# Latest 는 `--prev` 로 준다. 망 · cargo 를 쓰지 않는다. Git Bash · 리눅스 어디서나 돈다.
#
# 종료 코드: 0 = 모든 경우가 기대대로 · 1 = 하나라도 아니다 · 2 = 저장소 루트에서 부르지 않았다.
set -u
for f in ci/release-notes.sh .github/release-notes.md README.md Cargo.toml; do
    [ -f "$f" ] || { echo "$f 가 없다 — 저장소 루트에서 부를 것" >&2; exit 2; }
done
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
BASE="$W/base"
mkdir -p "$BASE/ci" "$BASE/.github"
cp ci/release-notes.sh "$BASE/ci/"
cp .github/release-notes.md "$BASE/.github/"
cp Cargo.toml "$BASE/"
cp -r plugins "$BASE/plugins"
sed -n '/<!-- threats:begin/,/<!-- threats:end -->/p' README.md | sed '1d;$d' >"$BASE/table.md"

# 두 종류의 칸 본문 — 엔진(위협 소제목 · 프로그램 · 접는 블록 둘)과 룰만(위협 소제목 · 그 밖). 줄 끝의 \ 는 칸 규칙의 항목 안
# 줄바꿈이다(칸마다 둘 — 본문에 그대로 옮겨지는지 render 가 센다).
printf '%s\n' \
    '### 프로그램' \
    '' \
    '* **검사 엔진의 구성 요소 업데이트**\' \
    '  구성 요소를 보안 고침이 든 버전으로 올렸습니다.' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 화면 · 결과 파일 · 종료 코드는 이전 버전과 같습니다.' \
    '' \
    '</details>' \
    '' \
    '### 시험 점검' \
    '' \
    '* **시험 항목 탐지** (Windows)\' \
    '  시험 문장입니다.' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 판정 기준은 이전 버전과 같습니다.' \
    '' \
    '</details>' >"$BASE/engine.md"
printf '%s\n' \
    '### 시험 점검' \
    '' \
    '* **시험 항목 점검** (Linux)\' \
    '  시험 문장입니다.' \
    '' \
    '### 그 밖' \
    '' \
    '* **릴리스 이름의 꼴 정리**\' \
    '  시험 문장입니다.' >"$BASE/rules.md"

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  OK   $1"; }
ng() { fail=$((fail + 1)); echo "  FAIL $1"; }

# 두 종류 태그(rc 꼬리 포함) 모두 종료 0 · 비교 구간 · 소제목 · 방식 칸 · 남은 자리 없음 · 항목 안 줄바꿈(줄 끝의 \ 하나 — 칸마다
# 둘 · 틀과 표에는 없다)이 그대로 · 릴리스 목록 주소.
render() { # 태그 · 비교 구간 줄의 정규식(ERE) · 기대 소제목 수 · 스크립트 인자…
    local tag=$1 since=$2 h3=$3 out code
    shift 3
    out=$(cd "$BASE" && bash ci/release-notes.sh "$tag" --table table.md "$@" 2>&1)
    code=$?
    if [ "$code" = 0 ] && grep -qE "$since" <<<"$out" && [ "$(grep -c '^### ' <<<"$out")" = "$h3" ] &&
        grep -qE '^\| [^|]+ \| 방식 \| Windows \| Linux \| [^|]+ \|$' <<<"$out" && ! grep -q '{{' <<<"$out" &&
        [ "$(grep -c '[\]$' <<<"$out")" = 2 ] && ! grep -q '[\][\]$' <<<"$out" &&
        grep -qF '(https://github.com/ESTsecurity/remedy/releases)' <<<"$out"; then
        ok "본문 $tag — 종료 0 · $(grep -m1 '^## 2\.' <<<"$out") · 소제목 $h3"
    else
        ng "본문 $tag — 종료 $code · $(grep -m1 '::error::' <<<"$out" | cut -c1-150)"
    fi
}
render rules-2099.01.01 '^## 2\. 변경 내용 \(`룰 2026\.11\.21` → `룰 2099\.01\.01`\)$' 2 \
    --prev rules-2026.11.21 --engine 1.25.3 --changes rules.md
render rules-2099.01.01-rc.1 '^## 2\. 변경 내용 \(`룰 2026\.11\.21` → `룰 2099\.01\.01`\)$' 2 \
    --prev rules-2026.11.21 --engine 1.25.3 --changes rules.md
render v9.9.9 '^## 2\. 변경 내용 \(`룰 2099\.01\.01` → `프로그램 9\.9\.9`\)$' 2 \
    --prev rules-2099.01.01 --engine 9.9.9 --rules 2099.01.01 --changes engine.md
render v9.9.9-rc.1 '^## 2\. 변경 내용 \(`프로그램 1\.25\.3` → `프로그램 9\.9\.9`\)$' 2 \
    --prev v1.25.3 --engine 9.9.9 --rules 2099.01.01 --changes engine.md

# 멈춤 장치 — 사본을 하나씩 깨뜨려 종료 1(값이 모자라면 2)과 그 까닭이 나오는지.
guard() { # 이름 · 기대 종료 코드 · 기대 낱말 · 사본을 고치는 셸 · 스크립트 인자…
    local name=$1 want_code=$2 want=$3 edit=$4 d="$W/$1" out code
    shift 4
    rm -rf "$d"
    cp -r "$BASE" "$d"
    (cd "$d" && eval "$edit") || { ng "$name — 준비 실패"; return; }
    out=$(cd "$d" && bash ci/release-notes.sh "$@" 2>&1 >/dev/null)
    code=$?
    if [ "$code" = "$want_code" ] && grep -qF -- "$want" <<<"$out"; then ok "멈춤 $name — 종료 $code"; else ng "멈춤 $name — 종료 $code · $(cut -c1-150 <<<"$out")"; fi
    rm -rf "$d"
}
R=(rules-2099.01.01 --prev rules-2026.11.21 --engine 1.25.3 --table table.md)
add_line() { printf '\n%s\n' "$1" >>rules.md; }
FENCE='```'
guard no-changes 1 "조각이 없다" ": > rules.md" "${R[@]}" --changes rules.md
guard unknown-job 1 "모르는 문구" "sed -i '0,/| 찾기만 합니다 |/s//| 찾습니다 |/' table.md" "${R[@]}" --changes rules.md
guard head-swapped 1 "위협 표의 머리가" "sed -i 's/^| 룰 | 하는 일 | Windows | Linux | \(.*\)|\$/| 룰 | 하는 일 | Linux | Windows | \1|/' table.md" "${R[@]}" --changes rules.md
guard no-table 1 "위협 표를 짓지 못했다" ": > table.md" "${R[@]}" --changes rules.md
guard open-fence 1 "닫히지 않은 코드 블록" "add_line '$FENCE'" "${R[@]}" --changes rules.md
guard details-mismatch 1 "짝이 맞지 않는다" "add_line '<details>'" "${R[@]}" --changes rules.md
guard relative-link 1 "상대 링크" "add_line '* 자세한 것은 [안내](docs/a.md) 에 있습니다.'" "${R[@]}" --changes rules.md
guard leftover-slot 1 "채우지 못한 자리" "printf '\n{{FOO}}\n' >> .github/release-notes.md" "${R[@]}" --changes rules.md
guard v-without-rules 2 "룰 버전이 없다" ":" v9.9.9 --prev v1.25.3 --engine 9.9.9 --table table.md --changes engine.md
guard rules-mismatch 2 "다르다" ":" rules-2099.01.01 --rules 2099.01.02 --prev rules-2026.11.21 --table table.md --changes rules.md

# 머리의 다섯째 칸 이름만 바뀌면 멈추지 않고 그 이름을 옮긴다(칸 차례가 그대로면 판정이 같다).
d="$W/head-renamed"
cp -r "$BASE" "$d"
sed -i 's/^| 룰 | 하는 일 | Windows | Linux | [^|]* |$/| 룰 | 하는 일 | Windows | Linux | 출처 |/' "$d/table.md"
out=$(cd "$d" && bash ci/release-notes.sh "${R[@]}" --changes rules.md 2>&1)
if [ $? = 0 ] && grep -qx '| 룰 | 방식 | Windows | Linux | 출처 |' <<<"$out"; then ok "머리 다섯째 칸 이름만 바뀜 — 종료 0 · 그 이름을 옮긴다"; else ng "머리 다섯째 칸 이름만 바뀜"; fi

echo "합: 통과 $pass · 실패 $fail"
[ "$fail" = 0 ]
