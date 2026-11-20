#!/bin/bash
# ci/release-notes.sh 의 시험 — 저장소 밖 임시 폴더에 그 스크립트가 읽는 파일을 옮겨, 새 꼴 칸 두 종류(룰만 · 엔진)의 본문이
# 지어지는지와 멈춤 장치마다 멈추는지 본다.
#
#   bash ci/release-notes-test.sh      (저장소 루트에서)
#
# 지금 README 의 위협 표와 룰 매니페스트를 그대로 쓴다 — 표 머리 · '하는 일' 문구(`xtask/src/threats.rs` 가 짓는다)가 스크립트의
# 칸 읽기 · `job_ko` 와 어긋나면 여기서 깨진다(PR 의 CI 가 돌린다 · 배포의 초안 잡은 태그에서만 돌아 그 전에는 알 수 없다).
# 업데이트 내역에는 가짜 버전(룰 2099.1.1 · 엔진 9.9.9)의 칸을 맨 위에 넣고, 룰 버전 · 엔진 버전도 그 값으로 바꾼다 — 지금
# 저장소의 버전에 칸이 있는지와 상관없이 돈다. 망을 쓰지 않는다. Git Bash · 리눅스 어디서나 돈다.
#
# 종료 코드: 0 = 모든 경우가 기대대로 · 1 = 하나라도 아니다 · 2 = 저장소 루트에서 부르지 않았다.
set -u
for f in ci/release-notes.sh .github/release-notes.md docs/업데이트-내역.md README.md Cargo.toml plugins/RULES-VERSION; do
    [ -f "$f" ] || { echo "$f 가 없다 — 저장소 루트에서 부를 것" >&2; exit 2; }
done
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
BASE="$W/base"
mkdir -p "$BASE/ci" "$BASE/.github" "$BASE/docs"
cp ci/release-notes.sh "$BASE/ci/"
cp .github/release-notes.md "$BASE/.github/"
cp README.md Cargo.toml "$BASE/"
cp -r plugins "$BASE/plugins"

# 새 꼴 칸 둘 — 엔진(위협 소제목 · 프로그램 · 접는 블록 둘)과 룰만(위협 소제목 · 그 밖). 줄 끝의 \ 는 칸 규칙의 항목 안 줄바꿈이다
# (칸마다 둘 — 본문에 그대로 옮겨지는지 render 가 센다). awk 에는 ENVIRON 으로 넘긴다 — `-v` 는 역슬래시를 풀어 줄 끝의 \ 를 지운다.
entries=(
    '## 9.9.9 · 룰 2099.1.1 — 2099-01-02'
    ''
    '### 프로그램'
    ''
    '* **검사 엔진의 구성 요소 업데이트**\'
    '  구성 요소를 보안 고침이 든 버전으로 올렸습니다.'
    ''
    '<details>'
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>'
    ''
    '* 화면 · 결과 파일 · 종료 코드는 이전 버전과 같습니다.'
    ''
    '</details>'
    ''
    '### 시험 점검'
    ''
    '* **시험 항목 탐지** (Windows)\'
    '  시험 문장입니다.'
    ''
    '<details>'
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>'
    ''
    '* 판정 기준은 이전 버전과 같습니다.'
    ''
    '</details>'
    ''
    '## 룰 2099.1.1 · 프로그램 1.0.0 — 2099-01-01'
    ''
    '### 시험 점검'
    ''
    '* **시험 항목 점검** (Linux)\'
    '  시험 문장입니다.'
    ''
    '### 그 밖'
    ''
    '* **릴리스 이름의 꼴 정리**\'
    '  시험 문장입니다.'
    ''
)
BLOCK="$(printf '%s\n' "${entries[@]}")" awk '!done && /^## / { print ENVIRON["BLOCK"]; done = 1 } { print }' \
    docs/업데이트-내역.md >"$BASE/docs/업데이트-내역.md"
printf '2099.1.1\n' >"$BASE/plugins/RULES-VERSION"
sed -i '0,/^\s*version = "[^"]*"/s//version = "9.9.9"/' "$BASE/Cargo.toml"

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  OK   $1"; }
ng() { fail=$((fail + 1)); echo "  FAIL $1"; }

# 새 꼴 칸 — 두 종류 태그(rc 꼬리 포함) 모두 종료 0 · 비교 구간 · 소제목 · 방식 칸 · 남은 자리 없음 · 항목 안 줄바꿈(줄 끝의
# \ 하나 — 칸마다 둘 · 틀과 README 표에는 없다)이 그대로. 비교 구간의 앞 칸은 그 파일에서 바로 아래 칸이다 — 룰 칸의 아래는
# 저장소의 실제 최신 칸이라 끝 버전만 본다.
render() { # 태그 · 비교 구간 줄의 정규식(ERE) · 기대 소제목 수
    local tag=$1 since=$2 h3=$3 out code
    out=$(cd "$BASE" && bash ci/release-notes.sh "$tag" 2>&1)
    code=$?
    if [ "$code" = 0 ] && grep -qE "$since" <<<"$out" && [ "$(grep -c '^### ' <<<"$out")" = "$h3" ] &&
        grep -qE '^\| [^|]+ \| 방식 \| Windows \| Linux \| [^|]+ \|$' <<<"$out" && ! grep -q '{{' <<<"$out" &&
        [ "$(grep -c '[\]$' <<<"$out")" = 2 ] && ! grep -q '[\][\]$' <<<"$out"; then
        ok "본문 $tag — 종료 0 · $(grep -m1 '^## 2\.' <<<"$out") · 소제목 $h3"
    else
        ng "본문 $tag — 종료 $code · $(grep -m1 '::error::' <<<"$out" | cut -c1-150)"
    fi
}
render rules-2099.1.1 '^## 2\. 변경 내용 \(`[^`]+` → `룰 2099\.1\.1`\)$' 2
render rules-2099.1.1-rc.1 '^## 2\. 변경 내용 \(`[^`]+` → `룰 2099\.1\.1`\)$' 2
render v9.9.9 '^## 2\. 변경 내용 \(`룰 2099\.1\.1` → `프로그램 9\.9\.9`\)$' 2

# 멈춤 장치 — 사본을 하나씩 깨뜨려 종료 1 과 그 까닭이 나오는지.
guard() { # 이름 · 기대 낱말 · 사본을 고치는 셸
    local name=$1 want=$2 edit=$3 d="$W/$1" out code
    rm -rf "$d"
    cp -r "$BASE" "$d"
    (cd "$d" && eval "$edit") || { ng "$name — 준비 실패"; return; }
    out=$(cd "$d" && bash ci/release-notes.sh rules-2099.1.1 2>&1 >/dev/null)
    code=$?
    if [ "$code" = 1 ] && grep -qF -- "$want" <<<"$out"; then ok "멈춤 $name — 종료 1"; else ng "멈춤 $name — 종료 $code · $(cut -c1-150 <<<"$out")"; fi
    rm -rf "$d"
}
add_line() { # 업데이트 내역의 룰 2099.1.1 칸(멈춤 시험이 짓는 칸)의 첫 '### ' 아래에 한 줄
    ADD="$1" awk '/^## 룰 2099\.1\.1 / { r = 1 } { print } r && /^### / && !d { print ""; print ENVIRON["ADD"]; d = 1 }' \
        docs/업데이트-내역.md >t && mv t docs/업데이트-내역.md
}
FENCE='```'
guard no-entry "칸이 없다" "printf '2099.9.9\n' > plugins/RULES-VERSION"
guard unknown-job "모르는 문구" "sed -i '0,/| 찾기만 합니다 |/s//| 찾습니다 |/' README.md"
guard head-swapped "위협 표의 머리가" "sed -i 's/^| 룰 | 하는 일 | Windows | Linux | \(.*\)|\$/| 룰 | 하는 일 | Linux | Windows | \1|/' README.md"
guard open-fence "닫히지 않은 코드 블록" "add_line '$FENCE'"
guard details-mismatch "짝이 맞지 않는다" "add_line '<details>'"
guard relative-link "상대 링크" "add_line '* 자세한 것은 [안내](docs/a.md) 에 있습니다.'"
guard leftover-slot "채우지 못한 자리" "printf '\n{{FOO}}\n' >> .github/release-notes.md"

# 머리의 다섯째 칸 이름만 바뀌면 멈추지 않고 그 이름을 옮긴다(칸 차례가 그대로면 판정이 같다).
d="$W/head-renamed"
cp -r "$BASE" "$d"
sed -i 's/^| 룰 | 하는 일 | Windows | Linux | [^|]* |$/| 룰 | 하는 일 | Windows | Linux | 출처 |/' "$d/README.md"
out=$(cd "$d" && bash ci/release-notes.sh rules-2099.1.1 2>&1)
if [ $? = 0 ] && grep -qx '| 룰 | 방식 | Windows | Linux | 출처 |' <<<"$out"; then ok "머리 다섯째 칸 이름만 바뀜 — 종료 0 · 그 이름을 옮긴다"; else ng "머리 다섯째 칸 이름만 바뀜"; fi

echo "합: 통과 $pass · 실패 $fail"
[ "$fail" = 0 ]
