#!/bin/bash
# ci/release-notes.sh 의 시험 — 저장소 밖 임시 폴더에 그 스크립트가 읽는 파일을 옮겨, 두 종류(룰만 · 엔진)의 본문이 지어지는지와
# 멈춤 장치마다 멈추는지 본다.
#
#   bash ci/release-notes-test.sh      (저장소 루트에서)
#
# 위협 표는 배포 잡과 같은 `cargo xtask threats --print`(지금 트리의 룰 매니페스트 — 표 머리 · '하는 일' 문구가 스크립트의 칸
# 읽기 · `job_ko` 와 어긋나면 여기서 깨진다)를 `--table` 로 주고, 바뀐 내용은 두 종류의 칸 본문을 `--changes` 로 준다(배포
# 잡은 `cargo xtask changes` 로 짓는다). README 의 표는 하루 한 번 짓는 생성물이라 하루 늦을 수 있어 쓰지 않는다 — 룰
# 폴더를 지우거나 이름을 바꾼 PR 에서 옛 줄 때문에 잘못 멈췄다(2026-11-21 반박 검토). 버전은 가짜 값(룰 2099.01.01 · 엔진
# 9.9.9)이고 지금 Latest 는 `--prev` 와 그 Release 이름 `--prev-name` 으로 준다. 망을 쓰지 않는다 — cargo 는 그 표를 짓는 데만
# 쓴다. Git Bash · 리눅스에서 돈다.
#
# 2절은 머리의 버전 줄(프로그램 · 룰 칸마다 지난 공개본 → 이 출시)과 짧은 꼴(첫 화면은 칸마다 제목 줄 · 그 아래 알아두실 점 접기와
# 자세한 내용 접기)을 기대 본문과 바이트로 견준다 — 기대 본문은 아래 *.exp 다.
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
if ! cargo xtask threats --print 2>/dev/null | tr -d '\r' | sed '/^$/d' >"$BASE/table.md" || [ ! -s "$BASE/table.md" ]; then
    echo "위협 표를 짓지 못했다 — cargo xtask threats --print" >&2
    exit 2
fi

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
# 짧은 꼴의 가장자리 — 한 칸에 항목 둘(알아두실 점은 제 항목의 제목과 함께 알아두실 점 접기로 · 나머지는 자세한 내용 접기로) ·
# 다른 꼴의 접기(펴지 않고 남긴다) · 제목뿐인 칸(접기가 없다) · 문단과 코드 블록 안의 '* '(제목이 아니다).
printf '%s\n' \
    '### 프로그램' \
    '' \
    '* **A** (Linux)\' \
    '  설명 A.' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 A' \
    '' \
    '</details>' \
    '' \
    '* **B**\' \
    '  설명 B.' \
    '  * 하위 B' \
    '' \
    '<details><summary><b>Windows 에서</b></summary>' \
    '' \
    '* 다른 꼴' \
    '' \
    '</details>' \
    '' \
    '### 시험 점검' \
    '' \
    '* **제목만** (Linux)' \
    '' \
    '### 그 밖' \
    '' \
    '설명 문단입니다.' \
    '' \
    '```text' \
    '* 코드 안의 별표' \
    '```' \
    '' \
    '* **C**' >"$BASE/edge.md"
# 알아두실 점 접기의 한 줄 꼴(`<details><summary>…</summary>` — 룰 조각의 꼴)과 닫는 줄의 꼴 — 들여 쓴 닫는 줄 · 끝 공백이 붙은
# 닫는 줄은 펴고, 글과 같은 줄에서 닫는 접기는 펴지 않고 원문 그대로 둔다(여는 줄만 지우면 짝이 어긋나 태그를 민 뒤에야 멈춘다).
printf '%s\n' \
    '### 프로그램' \
    '' \
    '* **A** (Linux)\' \
    '  설명 A.' \
    '' \
    '<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 A' \
    '' \
    '  </details>' \
    '' \
    '### 시험 점검' \
    '' \
    '* **B**\' \
    '  설명 B.' \
    '' \
    '<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 B' \
    '' \
    '</details> ' \
    '' \
    '### 그 밖' \
    '' \
    '* **C**' \
    '' \
    '<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 C</details>' >"$BASE/close.md"
# 알아두실 점 접기를 어디에 두나 — 한 칸에 알아두실 점이 있는 조각 둘(둘 다 알아두실 점 접기에 제 제목과 하위 줄로, 원문 차례) ·
# 알아두실 점만 있고 설명이 없는 칸(알아두실 점 접기만) · 설명만 있는 칸(자세한 내용 접기만) · 같은 줄에서 닫는 접기(펴지 않고
# 자세한 내용 접기에 원문 그대로 · 알아두실 점 접기에 없다) · 앞에 꼭대기 항목이 없는 접기(딸릴 제목이 없어 펴지 않는다) ·
# 항목 여럿 뒤의 접기 하나(어느 항목의 것인지 몰라 제목 없이 원문 그대로 · 공개한 엔진 조각의 꼴 — 그 뒤 항목 하나의 접기는 제
# 제목과) · 한 항목 뒤의 접기 둘(제목 한 번 · 뒤 덩이는 빈 줄 하나를 두고 같은 들여쓰기로 잇는다) · 빈 접기 · 문단 뒤의 접기 · 코드
# 블록 안의 접기(항목 아래 들인 블록 · 들이지 않은 블록) · 다른 꼴 접기 안의 접기(넷 다 펴지 않는다) · 들인 코드 블록이나 다른 꼴
# 접기 뒤의 접기(그 안의 들이지 않은 줄이 목록을 끝내지 않아 제 제목과) · 설명 줄 바로 뒤의 접기(옮긴 뒤의 빈 줄을 남긴다) · 옮긴
# 접기 뒤의 들이지 않은 문단(잇기와 목록을 끊어 그 뒤 접기는 자세한 내용 접기에 원문 그대로) · 항목 여럿 뒤의 접기 둘(제목 없이 ·
# 뒤 덩이도 들이지 않고 빈 줄 하나 뒤에 — 빈 줄이 없으면 뒤 문단이 앞 항목에 붙는다).
printf '%s\n' \
    '### 시험 점검' \
    '' \
    '* **A** (Linux)\' \
    '  설명 A.' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 A1' \
    '* 알 A2' \
    '' \
    '</details>' \
    '' \
    '* **B**\' \
    '  설명 B.' \
    '' \
    '<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 B' \
    '' \
    '</details>' \
    '' \
    '### 프로그램' \
    '' \
    '* **C** (Windows)' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 C' \
    '' \
    '</details>' \
    '' \
    '### 그 밖' \
    '' \
    '* **D**' \
    '  * 하위 D' \
    '' \
    '### 다른 점검' \
    '' \
    '* **E**' \
    '' \
    '<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 E</details>' \
    '' \
    '* **F**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 F' \
    '' \
    '</details>' \
    '' \
    '### 앞 항목 없음' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 G' \
    '' \
    '</details>' \
    '' \
    '* **G**' \
    '' \
    '### 항목 여럿' \
    '' \
    '* **H1**' \
    '  설명 H1.' \
    '* **H2**' \
    '  설명 H2.' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 H' \
    '  * 알 H 하위' \
    '' \
    '</details>' \
    '' \
    '* **H3**' \
    '' \
    '<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 H3' \
    '' \
    '</details>' \
    '' \
    '### 알아두실 점 둘' \
    '' \
    '* **I**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 I1' \
    '' \
    '</details>' \
    '' \
    '<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 I2' \
    '' \
    '</details>' \
    '' \
    '### 빈 알아두실 점' \
    '' \
    '* **J**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '</details>' \
    '' \
    '### 문단 뒤 접기' \
    '' \
    '* **K**' \
    '' \
    '문단 L 입니다.' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 L' \
    '' \
    '</details>' \
    '' \
    '### 코드 안의 접기' \
    '' \
    '* **M**' \
    '  설명 M.' \
    '' \
    '  ```text' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '* 들인 코드 안의 접기' \
    '</details>' \
    '  ```' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 M' \
    '' \
    '</details>' \
    '' \
    '```text' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '* 코드 안의 접기' \
    '</details>' \
    '```' \
    '' \
    '### 다른 꼴 접기 뒤' \
    '' \
    '* **Q**' \
    '' \
    '<details><summary><b>Windows 에서</b></summary>' \
    '' \
    '* 다른 꼴 Q' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 Q' \
    '' \
    '</details>' \
    '' \
    '### 접기 안의 접기' \
    '' \
    '* **N**' \
    '' \
    '<details><summary><b>Windows 에서</b></summary>' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 N' \
    '' \
    '</details>' \
    '' \
    '</details>' \
    '' \
    '### 빈 줄 없는 접기' \
    '' \
    '* **O**' \
    '  설명 O.' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 O' \
    '' \
    '</details>' \
    '' \
    '* **P**' \
    '' \
    '### 옮긴 접기 뒤 문단' \
    '' \
    '* **X**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 X' \
    '' \
    '</details>' \
    '' \
    '문단 X 입니다.' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 X 뒤' \
    '' \
    '</details>' \
    '' \
    '### 항목 여럿 뒤 접기 둘' \
    '' \
    '* **R1**' \
    '* **R2**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 R' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '문단 R 입니다.' \
    '' \
    '</details>' >"$BASE/notes.md"

# 기대 2절 본문(머리 줄 · '지난 버전의 변경 내용은' 줄 사이 — 틀의 앞뒤 빈 줄은 뺀다).
printf '%s\n' \
    '### 프로그램' \
    '' \
    '* **검사 엔진의 구성 요소 업데이트**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **검사 엔진의 구성 요소 업데이트**' \
    '  * 화면 · 결과 파일 · 종료 코드는 이전 버전과 같습니다.' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **검사 엔진의 구성 요소 업데이트**\' \
    '  구성 요소를 보안 고침이 든 버전으로 올렸습니다.' \
    '' \
    '</details>' \
    '' \
    '### 시험 점검' \
    '' \
    '* **시험 항목 탐지** (Windows)' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **시험 항목 탐지** (Windows)' \
    '  * 판정 기준은 이전 버전과 같습니다.' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **시험 항목 탐지** (Windows)\' \
    '  시험 문장입니다.' \
    '' \
    '</details>' >"$BASE/engine.exp"
printf '%s\n' \
    '### 시험 점검' \
    '' \
    '* **시험 항목 점검** (Linux)' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **시험 항목 점검** (Linux)\' \
    '  시험 문장입니다.' \
    '' \
    '</details>' \
    '' \
    '### 그 밖' \
    '' \
    '* **릴리스 이름의 꼴 정리**' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **릴리스 이름의 꼴 정리**\' \
    '  시험 문장입니다.' \
    '' \
    '</details>' >"$BASE/rules.exp"
printf '%s\n' \
    '### 프로그램' \
    '' \
    '* **A** (Linux)' \
    '* **B**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **A** (Linux)' \
    '  * 알 A' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **A** (Linux)\' \
    '  설명 A.' \
    '' \
    '* **B**\' \
    '  설명 B.' \
    '  * 하위 B' \
    '' \
    '<details><summary><b>Windows 에서</b></summary>' \
    '' \
    '* 다른 꼴' \
    '' \
    '</details>' \
    '' \
    '</details>' \
    '' \
    '### 시험 점검' \
    '' \
    '* **제목만** (Linux)' \
    '' \
    '### 그 밖' \
    '' \
    '* **C**' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '설명 문단입니다.' \
    '' \
    '```text' \
    '* 코드 안의 별표' \
    '```' \
    '' \
    '* **C**' \
    '' \
    '</details>' >"$BASE/edge.exp"
printf '%s\n' \
    '### 프로그램' \
    '' \
    '* **A** (Linux)' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **A** (Linux)' \
    '  * 알 A' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **A** (Linux)\' \
    '  설명 A.' \
    '' \
    '</details>' \
    '' \
    '### 시험 점검' \
    '' \
    '* **B**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **B**' \
    '  * 알 B' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **B**\' \
    '  설명 B.' \
    '' \
    '</details>' \
    '' \
    '### 그 밖' \
    '' \
    '* **C**' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **C**' \
    '' \
    '<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 C</details>' \
    '' \
    '</details>' >"$BASE/close.exp"
printf '%s\n' \
    '### 시험 점검' \
    '' \
    '* **A** (Linux)' \
    '* **B**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **A** (Linux)' \
    '  * 알 A1' \
    '  * 알 A2' \
    '' \
    '* **B**' \
    '  * 알 B' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **A** (Linux)\' \
    '  설명 A.' \
    '' \
    '* **B**\' \
    '  설명 B.' \
    '' \
    '</details>' \
    '' \
    '### 프로그램' \
    '' \
    '* **C** (Windows)' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **C** (Windows)' \
    '  * 알 C' \
    '' \
    '</details>' \
    '' \
    '### 그 밖' \
    '' \
    '* **D**' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **D**' \
    '  * 하위 D' \
    '' \
    '</details>' \
    '' \
    '### 다른 점검' \
    '' \
    '* **E**' \
    '* **F**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **F**' \
    '  * 알 F' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **E**' \
    '' \
    '<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 E</details>' \
    '' \
    '* **F**' \
    '' \
    '</details>' \
    '' \
    '### 앞 항목 없음' \
    '' \
    '* **G**' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 G' \
    '' \
    '</details>' \
    '' \
    '* **G**' \
    '' \
    '</details>' \
    '' \
    '### 항목 여럿' \
    '' \
    '* **H1**' \
    '* **H2**' \
    '* **H3**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* 알 H' \
    '  * 알 H 하위' \
    '' \
    '* **H3**' \
    '  * 알 H3' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **H1**' \
    '  설명 H1.' \
    '* **H2**' \
    '  설명 H2.' \
    '' \
    '* **H3**' \
    '' \
    '</details>' \
    '' \
    '### 알아두실 점 둘' \
    '' \
    '* **I**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **I**' \
    '  * 알 I1' \
    '' \
    '  * 알 I2' \
    '' \
    '</details>' \
    '' \
    '### 빈 알아두실 점' \
    '' \
    '* **J**' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **J**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '</details>' \
    '' \
    '</details>' \
    '' \
    '### 문단 뒤 접기' \
    '' \
    '* **K**' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **K**' \
    '' \
    '문단 L 입니다.' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 L' \
    '' \
    '</details>' \
    '' \
    '</details>' \
    '' \
    '### 코드 안의 접기' \
    '' \
    '* **M**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **M**' \
    '  * 알 M' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **M**' \
    '  설명 M.' \
    '' \
    '  ```text' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '* 들인 코드 안의 접기' \
    '</details>' \
    '  ```' \
    '' \
    '```text' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '* 코드 안의 접기' \
    '</details>' \
    '```' \
    '' \
    '</details>' \
    '' \
    '### 다른 꼴 접기 뒤' \
    '' \
    '* **Q**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **Q**' \
    '  * 알 Q' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **Q**' \
    '' \
    '<details><summary><b>Windows 에서</b></summary>' \
    '' \
    '* 다른 꼴 Q' \
    '' \
    '</details>' \
    '' \
    '</details>' \
    '' \
    '### 접기 안의 접기' \
    '' \
    '* **N**' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **N**' \
    '' \
    '<details><summary><b>Windows 에서</b></summary>' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 N' \
    '' \
    '</details>' \
    '' \
    '</details>' \
    '' \
    '</details>' \
    '' \
    '### 빈 줄 없는 접기' \
    '' \
    '* **O**' \
    '* **P**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **O**' \
    '  * 알 O' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **O**' \
    '  설명 O.' \
    '' \
    '* **P**' \
    '' \
    '</details>' \
    '' \
    '### 옮긴 접기 뒤 문단' \
    '' \
    '* **X**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* **X**' \
    '  * 알 X' \
    '' \
    '</details>' \
    '' \
    '<details>' \
    '<summary><b>자세한 내용 보기</b></summary>' \
    '' \
    '* **X**' \
    '' \
    '문단 X 입니다.' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>' \
    '' \
    '* 알 X 뒤' \
    '' \
    '</details>' \
    '' \
    '</details>' \
    '' \
    '### 항목 여럿 뒤 접기 둘' \
    '' \
    '* **R1**' \
    '* **R2**' \
    '' \
    '<details>' \
    '<summary><b>알아두실 점</b></summary>' \
    '' \
    '* 알 R' \
    '' \
    '문단 R 입니다.' \
    '' \
    '</details>' >"$BASE/notes.exp"

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  OK   $1"; }
ng() { fail=$((fail + 1)); echo "  FAIL $1"; }

# 2절의 본문 — 머리 줄 다음부터 '지난 버전의 변경 내용은' 줄 앞까지(앞뒤 빈 줄 하나씩은 틀의 것이라 뗀다).
section2() { sed -n '/^## 2\. /,/^지난 버전의 변경 내용은 /p' | sed '1d;$d' | sed '1{/^$/d};${/^$/d}'; }

# 두 종류 태그(rc 꼬리 포함) 모두 종료 0 · 버전 줄 · 소제목 · 2절 본문 · 방식 칸 · 남은 자리 없음 · 항목 안 줄바꿈(줄 끝의 \ 하나
# — 접기 안의 원문에 칸마다 둘 · 첫 화면의 제목 줄은 뗀다 · 틀과 표에는 없다) · 릴리스 목록 주소.
render() { # 태그 · 버전 줄의 정규식(ERE) · 기대 소제목 수 · 기대 2절 본문 · 스크립트 인자…
    local tag=$1 since=$2 h3=$3 want=$4 out code
    shift 4
    out=$(cd "$BASE" && bash ci/release-notes.sh "$tag" --table table.md "$@" 2>&1)
    code=$?
    if [ "$code" = 0 ] && grep -qE "$since" <<<"$out" && [ "$(grep -c '^### ' <<<"$out")" = "$h3" ] &&
        [ "$(section2 <<<"$out")" = "$(cat "$BASE/$want")" ] &&
        grep -qE '^\| [^|]+ \| 방식 \| Windows \| Linux \| [^|]+ \|$' <<<"$out" && ! grep -q '{{' <<<"$out" &&
        [ "$(grep -c '[\]$' <<<"$out")" = 2 ] && ! grep -q '[\][\]$' <<<"$out" &&
        grep -qF '(https://github.com/ESTsecurity/remedy/releases)' <<<"$out"; then
        ok "본문 $tag · $want — 종료 0 · $(grep -m1 '^## 2\.' <<<"$out") · 소제목 $h3"
    else
        ng "본문 $tag · $want — 종료 $code · $(grep -m1 '^## 2\.' <<<"$out") · $(grep -m1 '::error::' <<<"$out" | cut -c1-150)"
        [ "$code" != 0 ] || diff <(section2 <<<"$out") "$BASE/$want" | head -8 | sed 's/^/       /'
    fi
}
P='프로그램 1.25.3 · 룰 2026.11.21'
render rules-2099.01.01 '^## 2\. 변경 내용 \(프로그램 1\.25\.3 그대로 · 룰 2026\.11\.21 → 2099\.01\.01\)$' 2 rules.exp \
    --prev rules-2026.11.21 --prev-name "$P" --engine 1.25.3 --changes rules.md
# --engine 이 없는 룰 태그는 지난 공개본의 엔진이다(Cargo.toml 이 아니다 — 룰만 바뀐 출시가 싣는 것은 Latest 의 엔진).
render rules-2099.01.01-rc.1 '^## 2\. 변경 내용 \(프로그램 1\.25\.3 그대로 · 룰 2026\.11\.21 → 2099\.01\.01\)$' 2 rules.exp \
    --prev rules-2026.11.21 --prev-name "$P" --changes rules.md
render v9.9.9 '^## 2\. 변경 내용 \(프로그램 1\.25\.3 → 9\.9\.9 · 룰 2099\.01\.01 그대로\)$' 2 engine.exp \
    --prev rules-2099.01.01 --prev-name '프로그램 1.25.3 · 룰 2099.01.01' --engine 9.9.9 --rules 2099.01.01 --changes engine.md
render v9.9.9-rc.1 '^## 2\. 변경 내용 \(프로그램 1\.25\.3 → 9\.9\.9 · 룰 2026\.11\.21 → 2099\.01\.01\)$' 2 engine.exp \
    --prev v1.25.3 --prev-name "$P" --engine 9.9.9 --rules 2099.01.01 --changes engine.md
render rules-2099.01.01 '^## 2\. 변경 내용 \(프로그램 1\.25\.3 그대로 · 룰 2026\.11\.21 → 2099\.01\.01\)$' 3 edge.exp \
    --prev rules-2026.11.21 --prev-name "$P" --engine 1.25.3 --changes edge.md
render rules-2099.01.01 '^## 2\. 변경 내용 \(프로그램 1\.25\.3 그대로 · 룰 2026\.11\.21 → 2099\.01\.01\)$' 3 close.exp \
    --prev rules-2026.11.21 --prev-name "$P" --engine 1.25.3 --changes close.md
render rules-2099.01.01 '^## 2\. 변경 내용 \(프로그램 1\.25\.3 그대로 · 룰 2026\.11\.21 → 2099\.01\.01\)$' 15 notes.exp \
    --prev rules-2026.11.21 --prev-name "$P" --engine 1.25.3 --changes notes.md

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
R=(rules-2099.01.01 --prev rules-2026.11.21 --prev-name "$P" --engine 1.25.3 --table table.md)
add_line() { printf '\n%s\n' "$1" >>rules.md; }
FENCE='```'
guard no-changes 1 "조각이 없다" ": > rules.md" "${R[@]}" --changes rules.md
guard unknown-job 1 "모르는 문구" "sed -i '0,/| 찾기만 합니다 |/s//| 찾습니다 |/' table.md" "${R[@]}" --changes rules.md
guard head-swapped 1 "위협 표의 머리가" "sed -i 's/^| 룰 | 하는 일 | Windows | Linux | \(.*\)|\$/| 룰 | 하는 일 | Linux | Windows | \1|/' table.md" "${R[@]}" --changes rules.md
guard no-table 1 "위협 표를 짓지 못했다" ": > table.md" "${R[@]}" --changes rules.md
guard open-fence 1 "닫히지 않은 코드 블록" "add_line '$FENCE'" "${R[@]}" --changes rules.md
guard details-mismatch 1 "짝이 맞지 않는다" "add_line '<details>'" "${R[@]}" --changes rules.md
# 닫히지 않은 알아두실 점 접기 — 펴지 않으므로 마지막 확인이 짝을 본다(펴며 여는 줄을 지우면 짝이 맞아 보였다).
guard notes-unclosed 1 "짝이 맞지 않는다" "add_line '<details><summary><b>알아두실 점 및 자세한 내용 보기</b></summary>'" "${R[@]}" --changes rules.md
guard relative-link 1 "상대 링크" "add_line '* 자세한 것은 [안내](docs/a.md) 에 있습니다.'" "${R[@]}" --changes rules.md
guard leftover-slot 1 "채우지 못한 자리" "printf '\n{{FOO}}\n' >> .github/release-notes.md" "${R[@]}" --changes rules.md
guard v-without-rules 2 "룰 버전이 없다" ":" v9.9.9 --prev v1.25.3 --engine 9.9.9 --table table.md --changes engine.md
guard rules-mismatch 2 "다르다" ":" rules-2099.01.01 --rules 2099.01.02 --prev rules-2026.11.21 --table table.md --changes rules.md
# 지난 공개본의 이름 — 버전 줄의 지난 값을 그 이름에서 읽는다(뒤의 --prev-name 이 R 의 것을 덮는다).
guard prev-name-form 2 "'프로그램 <엔진> · 룰 <룰>' 꼴이 아니다" ":" "${R[@]}" --prev-name v1.25.3 --changes rules.md
guard prev-name-mismatch 2 "그 이름의 버전이 다르다" ":" "${R[@]}" --prev-name '프로그램 1.25.3 · 룰 2026.11.20' --changes rules.md

# 머리의 다섯째 칸 이름만 바뀌면 멈추지 않고 그 이름을 옮긴다(칸 차례가 그대로면 판정이 같다).
d="$W/head-renamed"
cp -r "$BASE" "$d"
sed -i 's/^| 룰 | 하는 일 | Windows | Linux | [^|]* |$/| 룰 | 하는 일 | Windows | Linux | 출처 |/' "$d/table.md"
out=$(cd "$d" && bash ci/release-notes.sh "${R[@]}" --changes rules.md 2>&1)
if [ $? = 0 ] && grep -qx '| 룰 | 방식 | Windows | Linux | 출처 |' <<<"$out"; then ok "머리 다섯째 칸 이름만 바뀜 — 종료 0 · 그 이름을 옮긴다"; else ng "머리 다섯째 칸 이름만 바뀜"; fi

echo "합: 통과 $pass · 실패 $fail"
[ "$fail" = 0 ]
