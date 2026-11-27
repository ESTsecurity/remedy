#!/bin/bash
# Linux 실기기 검증 — 수집부터 치료·복원까지 (설계-09 P12).
#
# Windows 쪽 `guest/Verify-P4~P8.ps1` + `host/Invoke-P10Verify.ps1` 이 하는
# 일을 Linux 에서 한 파일로 한다. 나눌 이유가 없다 — Windows 는 WinRM 너머로
# 게스트와 호스트가 갈리지만, 여기서는 컨테이너 안에서 전부 돈다.
#
# # 이것이 재는 것
#
# **Linux 에서 `apply` 가 한 번도 실기기에서 돈 적이 없다.** 쓰기 백엔드의
# 단위 시험은 전부 임시 디렉터리 위에서 돈다. 진짜 `/etc` · 진짜 systemd
# 유닛 · 진짜 cron 파일 · 진짜 프로세스 위에서 무엇이 일어나는지는 이 파일이
# 처음 본다.
#
# # 판정의 독립성
#
# 무엇이 바뀌었는지는 `capture-state.sh` 가 말한다. 그것은 remedy 를 부르지
# 않는다 — `stat` · `sha256sum` · `readlink` 만 쓴다. 검증자가 피검증자를
# 신뢰하면 검증이 아니다.
#
# # 이슈 #172 의 칸 (엔진 1.27.0 부터)
#
# 홈 찾기(A4 · A5 · A6 · A7) · 글롭 폴더 칸의 토큰(A8 · A9 · A10)과 리눅스 복원의 소유자 · 링크(D5 · D6 ·
# D7) · 꺼낸 사본(D8)이다. 1.27.0 이 고친 결함을 재므로 그 앞의 엔진이면 칸마다 `건너뜀 — 엔진 <판> < 1.27.0` 을 적고 판정하지
# 않는다 — 실패로 세지 않고 결과 JSON 에도 넣지 않는다(`host/Invoke-WinwyvernVerify.ps1` 의 H 칸과 같다). 엔진 판은 `--version` 의
# `<제품> <판> (remedy)` 줄에서 읽고, 읽지 못하면 멈춘다(종료 2 — 조용히 건너뛰지 않는다).
#
# **공개본에서 결함을 재현할 때만** 환경 `JUDGE_ALL=1` 로 판 게이트를 넘긴다(호스트에서는
# `JUDGE_ALL=1 invoke-linux-verify.sh --bin <공개본>` — 컨테이너로 넘겨 준다). 그 회차도 고친 판의 기대값으로
# 판정하므로 이 칸들의 실패가 곧 재현이다. F2(서명이 기능을 막지 않았다)는 이 칸들의 실패를 따로 센다.
#
#   A4  /home 바로 아래의 파일(쿼터의 aquota.* 자리 — `b`) 뒤의 홈 bob 의 timer(principal=bob) · 서비스 ·
#       자동실행이 담긴다
#   A5  /home 에 폴더만 있을 때 첫 홈 안의 점 폴더(~/.aaa)를 홈으로 담지 않는다 — 그 안의 미끼 timer 0건
#       (대조: bob 의 timer). /home 의 파일과 링크가 옛 걷기를 첫 홈 앞에서 끊어 A4 와 한 수집에서 함께
#       드러나지 않으므로, 그 둘을 잠시 치우고 따로 걷는다
#   A6  두 수집 모두 잘림이 서지 않는다
#   A7  홈 자리의 링크(test)를 홈으로 담지 않는다(첫 수집)
#   A8  `collect_extra` 글롭의 폴더 칸에 `%ALLUSERPROFILES%` 를 쓴 룰(`glob-plugin.yaml` · min_core 1.27.0)이
#       린트를 지난다 — 오류 0 · 경고 0. 1.27.0 앞의 엔진은 그 min_core 를 받지 않으므로 JUDGE_ALL 회차는
#       min_core 만 낮춘 사본을 쓴다(결과 폴더의 `glob-plugin-low.yaml`)
#   A9  그 룰의 collect 가 종료 0 이고 'scan_roots 밖' 줄이 0이다 — 폴더 칸을 펴지 않으면 원문 그대로
#       상한과 견줘 그 줄을 낸다(1.26.0)
#   A10 홈마다(alice · bob) 약 20 MB 의 `bin/remedy-lab-big.bin` 본문이 담긴다 — 기본 상한 8 MB 를 넘으므로
#       `max_size: 32MB` 가 펴진 홈마다 걸려야 하고, 레코드의 content_ref 가 그 홈의 파일 해시와 같아야 한다
#   D5  꺼내기(D3) 뒤 제자리로 복원한다 — 종료 0 · 실패 줄 0. CA 도구가 없는 이미지(C1 · C2b)는 종료 3 이고
#       실패 줄은 치료가 거부한 인증서 항목 하나뿐이어야 한다 — 복원도 같은 까닭으로 거부한다. 그 자리는 D5b 로
#       못 잼에 남긴다
#   D6  치료가 지운 자리마다 치료 전과 복원 뒤가 같다 — 종류 · 크기 · 해시 · mode · 소유자(uid:gid) · 링크가
#       가리키는 곳과 링크 자체의 소유자. alice 의 4755 도구 · www-data 의 640 파일 · bob 의 유닛 둘과 활성화
#       링크는 치료됐어야 한다(아니면 '치료되지 않음' 으로 적고 실패다)
#   D7  격리된 도구의 부모(/home/alice/bin)를 root 소유 빈 폴더(/etc/remedy-lab-d7)를 가리키는 alice 소유의
#       링크로 바꾸고 그 항목만 제자리 복원 — 종료 5 · 링크가 가리킨 자리에 생긴 것 0개 · 링크 그대로
#   D8  alice 의 4755 도구 항목을 컨테이너 안의 빈 폴더로 꺼낸 사본이 꺼낸 계정(root 회차는 0:0)의 것이고 setuid ·
#       setgid 가 없다 — D3 의 사본은 호스트가 붙인 폴더에 있어 소유자 · mode 를 믿을 수 없다. 파일 권능
#       (`security.capability`)은 이미지에 `setcap` 이 없어 코어 단위 시험만 잰다
#
# 칸 수는 엔진 1.27.0 부터 31 이다(CA 도구가 없는 이미지는 못 잼 C2b · D5b 를 더해 33). 그 앞의 엔진은 위 열하나를
# 건너뛰어 20 이다(CA 도구가 없으면 C2b 를 더해 21).
#
# # 쓰는 법 (컨테이너 안)
#
#     verify-linux.sh --bin /w/target-linux/release/remedy --out /w/out
#     JUDGE_ALL=1 verify-linux.sh --bin <공개본 remedy> --out /w/out     # 1.27.0 앞의 판에서 #172 를 재현
#
# 호스트에서는 `invoke-linux-verify.sh` 가 컨테이너를 띄워 이것을 부른다.

set -u
# 이 스크립트는 한국어 문구를 읽는다. 기본 언어는 영어다 (2026-09-06).
export REMEDY_LANG=ko

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN=""
OUT="/tmp/remedy-linux-verify"
FORCE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)   BIN="${2:-}"; shift 2 ;;
        --out)   OUT="${2:-}"; shift 2 ;;
        --force) FORCE="--force"; shift ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done

[ -n "$BIN" ] || { echo "--bin <remedy 경로> 가 필요하다."; exit 2; }
[ -x "$BIN" ] || { echo "실행할 수 없다: $BIN"; exit 2; }

# 이슈 #172 의 칸을 판정하는가(머리말). `JUDGE_ALL=1` 은 공개본에서 결함을 재현할 때만 쓴다.
NEW_SINCE=1.27.0
ENGINE="$("$BIN" --version 2>&1 \
    | sed -nE 's/.* ([0-9]+\.[0-9]+\.[0-9]+)(-[0-9A-Za-z.]+)? \(remedy\).*/\1/p' | head -1)"
[ -n "$ENGINE" ] || { echo "엔진 버전을 읽지 못했다(--version) — #172 칸을 돌릴지 정할 수 없다."; exit 2; }
# ENGINE_NEW 는 엔진이 그 판 이상인가 — JUDGE_ALL 로 판정하는 낮은 엔진과 가른다(A8 의 룰 사본).
if [ "$(printf '%s\n%s\n' "$NEW_SINCE" "$ENGINE" | sort -V | head -1)" = "$NEW_SINCE" ]; then
    ENGINE_NEW=1; JUDGE_NEW=1; JUDGE_WHY="판정 — 엔진 $ENGINE ≥ $NEW_SINCE"
elif [ "${JUDGE_ALL:-0}" = 1 ]; then
    ENGINE_NEW=0; JUDGE_NEW=1; JUDGE_WHY="판정 — JUDGE_ALL=1 · 엔진 $ENGINE 에서 결함을 재현한다"
else
    ENGINE_NEW=0; JUDGE_NEW=0; JUDGE_WHY="건너뜀 — 엔진 $ENGINE < $NEW_SINCE"
fi

mkdir -p "$OUT"
STATE="$OUT/state"
PLUGIN="$HERE/lab-plugin.yaml"

# ── 판정 기록 ───────────────────────────────────────────────────────
#
# Windows 쪽과 같은 모양으로 남긴다 — {name, ok, detail}. 결과 파일을 두
# 플랫폼이 같은 눈으로 읽을 수 있어야 한다.
RESULT="$OUT/verify-linux.json"
: > "$OUT/.checks"
PASS=0
FAIL=0
UNMEASURED=0

# 판정은 **셋**이다 — 통과 · 실패 · **잴 수 없었다.**
#
# 셋째가 없으면 잴 수 없던 것이 둘 중 하나로 접히고, 어느 쪽으로 접든 거짓말이
# 된다. 통과로 접으면 "재지 않았다" 가 "오탐이 없다" 로 읽히고, 실패로 접으면
# 고칠 것이 없는 자리를 계속 붉게 보여 사람이 실패를 무시하는 법을 배운다.
check() {
    local name="$1" ok="$2" detail="$3"
    case "$ok" in
        1) PASS=$((PASS + 1)); printf '  \033[32mOK\033[0m   %-46s %s\n' "$name" "$detail" ;;
        -) UNMEASURED=$((UNMEASURED + 1))
           printf '  \033[33m못잼\033[0m %-46s %s\n' "$name" "$detail" ;;
        *) FAIL=$((FAIL + 1)); printf '  \033[31m실패\033[0m %-46s %s\n' "$name" "$detail" ;;
    esac
    printf '%s\t%s\t%s\n' "$name" "$ok" "$detail" >> "$OUT/.checks"
}

# 이슈 #172 의 칸. 실패를 따로 세어 F2 가 그것을 '서명이 기능을 막았다' 로 읽지 않게 한다.
FAIL_NEW=0
SKIPPED=0
check_new() {
    case "$2" in 1|-) ;; *) FAIL_NEW=$((FAIL_NEW + 1)) ;; esac
    check "$@"
}
skip_new() {
    local n
    for n in "$@"; do
        SKIPPED=$((SKIPPED + 1))
        printf '  건너뜀 %-44s %s\n' "$n" "엔진 $ENGINE < $NEW_SINCE"
    done
}

# artifacts.json 의 한 절(`persistence` 등)에서 id 가 정확히 <id> 인 레코드의 칸 하나(따옴표째). 없으면 빈 값.
# 레코드는 들여쓰기 4칸의 `{` … `}` 이고 칸은 6칸이다(serde_json 의 예쁜 출력) — jq 없는 이미지를 전제한다.
# 열쇠 칸은 환경 REC_KEY 로 바꾼다 — `file` 절은 `path` 다(`REC_KEY=path rec_field …`).
rec_field() {
    awk -v sec="  \"$2\": [" -v id="      \"${REC_KEY:-id}\": \"$3\"," -v f="      \"$4\": " '
        index($0, sec) == 1 { insec = 1; next }
        insec && /^  []}]/ { insec = 0 }
        insec && /^    \{/ { buf = ""; inrec = 1 }
        insec && inrec { buf = buf $0 "\n" }
        insec && inrec && /^    \}/ {
            inrec = 0
            if (index(buf, id "\n")) {
                n = split(buf, L, "\n")
                for (i = 1; i <= n; i++)
                    if (index(L[i], f) == 1) { v = substr(L[i], length(f) + 1); sub(/,$/, "", v); print v }
            }
        }' "$1"
}

# ── 이 이미지가 잴 수 없는 것 ───────────────────────────────────────
#
# `cert_store.remove` 는 신뢰 저장소를 다시 만들 도구를 요구한다. 없으면 거부
# 하는 것이 **옳은 동작**이다 — 인증서 파일만 지우면 `ca-certificates.crt`
# 번들에 남아 신뢰가 사라지지 않고, 그러면 "제거했다" 는 보고가 거짓이 된다.
#
# 그래서 도구가 없는 이미지에서 이 자리는 실패가 아니라 **못 잰 것**이다.
CA_TOOL=""
for t in /usr/sbin/update-ca-certificates /usr/bin/update-ca-trust; do
    [ -x "$t" ] && CA_TOOL="$t" && break
done

# 계획 **actions 절**의 Op 만 뽑는다. jq 도 python3 도 없는 이미지를 전제한다.
#
# **절을 갈라 읽어야 한다.** plan.json 에는 `deferred` 절이 따로 있고 거기에도
# `"op"` 가 실린다 — 이 코어가 수행할 수 없어 미뤄 둔 것들이다. 파일 전체를
# 긁으면 미룬 것을 "계획했다" 로 세게 되고, 그러면 이 하네스가 **정확히 반대의
# 거짓말**을 한다. 첫 실행에서 실제로 그랬다.
ops_in() { sed -n '/^  "actions"/,/^  "[a-z_]*":/p' "$1" 2>/dev/null \
             | grep -o '"op"[[:space:]]*:[[:space:]]*"[a-z_.]*"' \
             | sed 's/.*"\([a-z_.]*\)"$/\1/' | sort -u; }

# 미룬 것. **0건이어야 한다** — 이 실험대는 리눅스가 수행할 수 있는 것만 겨눈다.
deferred_in() { sed -n '/^  "deferred"/,/^  "[a-z_]*":/p' "$1" 2>/dev/null \
             | grep -o '"op"[[:space:]]*:[[:space:]]*"[a-z_.]*"' \
             | sed 's/.*"\([a-z_.]*\)"$/\1/' | sort -u; }

# capture-state.sh 가 낸 JSON 에서 한 항목을 본다.
# present <파일> <경로>  → "true" / "false"
present() { grep -o "\"path\": \"$2\", \"present\": [a-z]*" "$1" | sed 's/.*: //' | head -1; }
# linecount <파일> <label> → 숫자
linecount() { grep -o "\"label\": \"$2\", [^}]*\"count\": [0-9]*" "$1" \
                | sed 's/.*"count": //' | head -1; }
# sha <파일> <경로> → 해시
sha() { grep -o "\"path\": \"$2\",[^}]*\"sha256\": \"[0-9a-f]*\"" "$1" \
          | sed 's/.*"sha256": "\([0-9a-f]*\)"/\1/' | head -1; }
# obj <파일> <경로> → 그 자리의 한 줄 전부(끝 쉼표 뺌). 경로는 정규식이 아니라 글자 그대로 견준다.
obj() { grep -F "{ \"path\": \"$2\", " "$1" | head -1 | sed 's/,$//'; }
# fld <obj 줄> <칸> → 따옴표 안의 값
fld() { printf '%s' "$1" | grep -o "\"$2\": \"[^\"]*\"" | sed 's/^[^:]*: "\(.*\)"$/\1/'; }
# 자리를 짧게 — 부모 폴더 이름/파일 이름(유닛과 그 활성화 링크는 이름이 같다).
lbl() { printf '%s/%s' "$(basename "$(dirname "$1")")" "$(basename "$1")"; }

echo
echo "═══ Linux 실기기 검증 ═══"
"$BIN" --version 2>&1 | sed 's/^/  /'
echo "  이미지  $( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-불명}" )"
echo "  PID 1   $(cat /proc/1/comm 2>/dev/null || echo 불명)"
echo "  #172 칸 $JUDGE_WHY"
echo

# ── 픽스처 ──────────────────────────────────────────────────────────
bash "$HERE/new-fixtures.sh" --clean $FORCE > /dev/null 2>&1
# 파이프의 종료 코드는 sed 의 것이다 — 픽스처 스크립트의 것을 본다.
bash "$HERE/new-fixtures.sh" $FORCE | sed 's/^/  /'
[ "${PIPESTATUS[0]}" -eq 0 ] || { echo "픽스처 생성 실패"; exit 1; }
bash "$HERE/capture-state.sh" > "$OUT/before.json"
echo

# ════════════════════════════════════════════════════════════════════
# A. 수집
# ════════════════════════════════════════════════════════════════════
echo "── A. 수집 ──"

"$BIN" collect --plugin "$PLUGIN" --out "$OUT/artifacts.json" > "$OUT/collect.log" 2>&1
rc=$?
check "A1 collect 가 성공한다" "$([ $rc -eq 0 ] && echo 1 || echo 0)" "exit=$rc"

# subject 마다 레코드가 나왔는가. **0건인 subject 는 "오탐이 없다" 가 아니라
# "재지 않았다" 다** — 이 구분을 흐리면 초록이 거짓말을 한다.
missing=""
for s in file text_config structured_config hosts_entry shortcut autorun \
         cert_store persistence service browser_extension process; do
    n=$(grep -o "\"$s\":[[:space:]]*\[" "$OUT/artifacts.json" > /dev/null 2>&1 && \
        sed -n "s/.*\"$s\"[[:space:]]*:[[:space:]]*\[\(.*\)/\1/p" "$OUT/artifacts.json" \
          | head -c 4 | grep -c '[^][:space:]]' || echo 0)
    grep -q "\"$s\"" "$OUT/artifacts.json" || missing="$missing $s"
done
check "A2 선언한 열한 subject 가 전부 담긴다" \
    "$([ -z "$missing" ] && echo 1 || echo 0)" \
    "$([ -z "$missing" ] && echo "빠짐 0건" || echo "빠짐:$missing")"

# 접근 거부가 있으면 "위협 없음" 을 말할 수 없다 (종료 코드 6).
den=$(grep -o '"denied_dirs"[[:space:]]*:[[:space:]]*[0-9]*' "$OUT/artifacts.json" \
        | sed 's/.*: *//' | sort -rn | head -1)
den="${den:-0}"
check "A3 접근 거부가 없다" "$([ "$den" = "0" ] && echo 1 || echo 0)" "denied_dirs=$den"

# ── 홈 찾기 (이슈 #172 · 엔진 1.27.0 부터) ──────────────────────────
#
# 홈은 `/home` 바로 아래의 폴더뿐이다. 픽스처는 new-fixtures.sh 12 절.
BU=/home/bob/.config
if [ "$JUDGE_NEW" = 1 ]; then
    a4_miss=""
    p="$(rec_field "$OUT/artifacts.json" persistence "$BU/systemd/user/remedy-lab-user.timer" principal)"
    [ "$p" = '"bob"' ] || a4_miss="$a4_miss timer(principal=${p:-없음})"
    [ -n "$(rec_field "$OUT/artifacts.json" service "$BU/systemd/user/remedy-lab-user.service" name)" ] \
        || a4_miss="$a4_miss service"
    [ -n "$(rec_field "$OUT/artifacts.json" autorun "$BU/autostart/remedy-lab-user.desktop" scope)" ] \
        || a4_miss="$a4_miss autorun"
    check_new "A4 /home 의 파일 뒤의 홈(bob)도 읽는다" \
        "$([ -z "$a4_miss" ] && echo 1 || echo 0)" \
        "$([ -z "$a4_miss" ] && echo "bob 의 timer(principal=bob) · service · autorun 3/3" \
           || echo "빠짐:$a4_miss")"

    # /home 의 파일은 옛 걷기를 /home 의 목록에서 끊어 첫 홈 안으로 내려가지 않게 한다 — 그래서 점 폴더가
    # 홈으로 담기는 결함은 /home 에 폴더만 있을 때 드러난다. **링크도 끊는다** — `DirEntry::metadata` 는
    # 링크를 따라가지 않아 옛 걷기가 링크를 파일로 셌다(1.26.0 · 2026-11-27 이 하네스에서 잼). 파일과 링크를
    # 잠시 치우고 한 번 더 걷는다.
    mv /home/b /tmp/remedy-lab-home-b && mv /home/test /tmp/remedy-lab-home-test \
        || { echo "/home 의 파일 · 링크를 치우지 못했다"; exit 1; }
    "$BIN" collect --plugin "$PLUGIN" --out "$OUT/artifacts-a5.json" > "$OUT/collect-a5.log" 2>&1
    rc5=$?
    mv /tmp/remedy-lab-home-b /home/b && mv /tmp/remedy-lab-home-test /home/test \
        || { echo "/home 의 파일 · 링크를 되돌리지 못했다"; exit 1; }
    # 레코드의 자리 칸만 센다 — 프로세스의 명령줄에도 경로가 실릴 수 있다.
    decoy="$(grep -c -e '"id": "/home/alice/\.aaa/' -e '"source": "/home/alice/\.aaa/' \
               "$OUT/artifacts-a5.json")"
    ctrl="$(rec_field "$OUT/artifacts-a5.json" persistence "$BU/systemd/user/remedy-lab-user.timer" principal)"
    check_new "A5 홈 안의 점 폴더(~/.aaa)를 홈으로 담지 않는다" \
        "$([ "$rc5" -eq 0 ] && [ "$decoy" = 0 ] && [ "$ctrl" = '"bob"' ] && echo 1 || echo 0)" \
        "미끼 ${decoy:-?}건 · 대조(bob 의 timer) principal=${ctrl:-없음} · /home 에 폴더만 두고 걸은 collect exit=$rc5"

    t1="$(grep -c '"truncated": true' "$OUT/artifacts.json")"
    t2="$(grep -c '"truncated": true' "$OUT/artifacts-a5.json")"
    check_new "A6 /home 의 파일이 잘림을 세우지 않는다" \
        "$([ "$t1" = 0 ] && [ "$t2" = 0 ] && echo 1 || echo 0)" \
        "잘림 ${t1:-?}건 · /home 에 폴더만 두고 ${t2:-?}건"

    # 링크 홈은 첫 수집(링크가 /home 에 있다)에서 본다 — 둘째 수집은 링크를 치웠다.
    l1="$(grep -c -e '"id": "/home/test/' -e '"source": "/home/test/' -e 'remedy-lab-linkhome\.timer' \
            "$OUT/artifacts.json")"
    check_new "A7 홈 자리의 링크(test)를 홈으로 담지 않는다" \
        "$([ "$l1" = 0 ] && echo 1 || echo 0)" "링크 홈의 레코드 ${l1:-?}건"
else
    skip_new "A4" "A5" "A6" "A7"
fi

# ── 글롭 폴더 칸의 토큰 (이슈 #172 ② · 엔진 1.27.0 부터) ────────────
#
# `glob-plugin.yaml` 이 `%ALLUSERPROFILES%/bin/remedy-lab-big*`(max_size 32MB)로 홈마다의 큰 자리 채우기를 담는다
# (new-fixtures.sh 13 절). 1.27.0 앞의 엔진은 그 룰의 min_core 를 받지 않고 멈추므로 — 그것은 결함이 아니라
# 로드 검사다 — JUDGE_ALL 회차는 min_core 만 낮춘 사본으로 결함 자체를 잰다.
if [ "$JUDGE_NEW" = 1 ]; then
    GP="$HERE/glob-plugin.yaml"; GP_NOTE=""
    if [ "$ENGINE_NEW" != 1 ]; then
        GP="$OUT/glob-plugin-low.yaml"; GP_NOTE=" · min_core 를 1.0.0 으로 낮춘 사본"
        sed 's/^min_core: "1\.27\.0"$/min_core: "1.0.0"/' "$HERE/glob-plugin.yaml" > "$GP"
    fi
    "$BIN" plugin lint "$GP" > "$OUT/lint-glob.log" 2>&1
    rcl=$?
    # 수만 읽는다 — 구분자는 로캘을 따른다(UTF-8 이 아닌 컨테이너에서는 `·` 가 `|` 다).
    sum="$(grep '^합계:' "$OUT/lint-glob.log" | tail -1)"
    le="$(printf '%s' "$sum" | sed -n 's/^합계: 오류 \([0-9]*\) .*/\1/p')"
    lw="$(printf '%s' "$sum" | sed -n 's/.* 경고 \([0-9]*\)$/\1/p')"
    check_new "A8 글롭 폴더 칸에 토큰을 쓴 룰이 린트를 지난다" \
        "$([ "$rcl" -eq 0 ] && [ "$le" = 0 ] && [ "$lw" = 0 ] && echo 1 || echo 0)" \
        "lint exit=$rcl · 오류 ${le:-?} · 경고 ${lw:-?}$GP_NOTE"

    "$BIN" collect --plugin "$GP" --out "$OUT/artifacts-glob.json" > "$OUT/collect-glob.log" 2>&1
    rcg=$?
    outside="$(grep -c 'scan_roots 밖' "$OUT/collect-glob.log")"
    check_new "A9 글롭 폴더 칸의 토큰을 편다 — 'scan_roots 밖' 0줄" \
        "$([ "$rcg" -eq 0 ] && [ "$outside" = 0 ] && echo 1 || echo 0)" \
        "collect exit=$rcg · 'scan_roots 밖' ${outside:-?}줄$GP_NOTE"

    # 레코드의 content_ref 가 그 홈 파일의 해시이고 그 본문이 blobs 에 있는가 — 홈마다 첫 줄이 달라 해시가 다르다.
    a10_bad=""; a10_n=0
    for u in alice bob; do
        p="/home/$u/bin/remedy-lab-big.bin"
        want="$(sha256sum "$p" 2>/dev/null | cut -d' ' -f1)"
        got="$(REC_KEY=path rec_field "$OUT/artifacts-glob.json" file "$p" content_ref)"
        if [ -n "$want" ] && [ "$got" = "\"sha256:$want\"" ] \
            && grep -q "\"sha256:$want\": \"" "$OUT/artifacts-glob.json"; then
            a10_n=$((a10_n + 1))
        else
            a10_bad="$a10_bad $u(${got:-본문 없음})"
        fi
    done
    check_new "A10 홈마다 그 홈의 본문이 담긴다(max_size 32MB)" \
        "$([ -z "$a10_bad" ] && echo 1 || echo 0)" \
        "$([ -z "$a10_bad" ] && echo "약 20 MB 본문 ${a10_n}/2 — 그 홈 파일의 해시" \
           || echo "빠짐:$a10_bad")"
else
    skip_new "A8" "A9" "A10"
fi

# ════════════════════════════════════════════════════════════════════
# B. 판정 · 계획
# ════════════════════════════════════════════════════════════════════
echo "── B. 판정 · 계획 ──"

"$BIN" scan --plugin "$PLUGIN" --out-dir "$OUT/scan" > "$OUT/scan.log" 2>&1
rc=$?
# 위협을 심어 뒀으므로 2(치료 안 함)가 정상이다. 0 이면 못 맞힌 것이다.
check "B1 판정이 선다" "$([ $rc -eq 2 ] && echo 1 || echo 0)" "scan exit=$rc (기대 2)"

PLAN="$OUT/scan/plan.json"
planned="$(ops_in "$PLAN" | tr '\n' ' ')"
echo "     계획 Op: $planned"

# 이 실험대가 겨눈 Op. Linux 계획 가능 13종 중 **결정 대상이 없는 둘**을 뺀 것.
#   file.delete                      격리가 언제나 먼저 뽑힌다 (NOT_PLANNABLE_YET)
#   structured_config.restore_default  기본값 카탈로그가 비었다 (NOT_PLANNABLE_YET)
WANT="file.quarantine_only text_config.remove_line structured_config.remove_key
hosts.restore_line shortcut.strip_args autorun.remove cert_store.remove
persistence.delete service.delete browser_ext.remove process.kill"
miss=""
for w in $WANT; do
    echo "$planned" | grep -qw "$w" || miss="$miss $w"
done
check "B2 기대 Op 이 전부 계획에 든다" \
    "$([ -z "$miss" ] && echo 1 || echo 0)" \
    "$([ -z "$miss" ] && echo "빠짐 0건 / $(echo $WANT | wc -w)종" || echo "빠짐:$miss")"

# 마커와 decoy 는 계획에 없어야 한다. **여기가 G3 의 앞쪽 절반**이다 —
# 계획 단계에서 이미 없으면, 치료가 건드릴 길이 없다.
#
# bob 의 자동실행(`remedy-lab-user.desktop`)은 수집되지만(A4) 어느 룰에도 걸리지 않는다 — 홈 찾기가 넓힌 자리의
# 남아야 할 것이다. 이것이 없으면 그 파일이 계획에 들어 격리되고 D5 가 같은 바이트로 되돌려도 모든 칸이 통과한다
# (autostart 조건을 `remedy-lab` 으로 넓힌 변이로 2026-11-27 에 잼).
bad=""
for d in "REMEDY-LAB.marker" "keepme.conf" "decoy-ca.crt" "innocent-cron" \
         "innocentinnocentinnocentinnoce" "remedy-lab-user.desktop"; do
    grep -q "$d" "$PLAN" && bad="$bad $d"
done
check "B3 남아야 할 것이 계획에 없다" \
    "$([ -z "$bad" ] && echo 1 || echo 0)" \
    "$([ -z "$bad" ] && echo "혼입 0건" || echo "혼입:$bad")"

# **미룸은 옳은 동작이다** — 수행할 수 없는 것을 했다고 하지 않는다. 그래서
# 0건을 요구하지 않고, **선언된 것만 미뤄졌는가**를 본다.
#
# 카탈로그가 `linux_from: None` 이라 적은 Op 은 여기 나오는 것이 정상이다.
# `service` 하나를 지우는 데 필요한 차례가 넷인데(stop → disable → delete →
# clear_recovery) Linux 에 개념이 있는 것은 둘뿐이다.
#
# 그 밖의 것이 나오면 다르다 — 그것은 **리눅스가 할 수 있다고 적어 놓고 못 한
# 것**이고, 그 자리는 잰 적이 없다는 뜻이다.
KNOWN_DEFER="service.stop service.clear_recovery"
defer="$(deferred_in "$PLAN" | tr '\n' ' ')"
unexpected=""
for d in $defer; do
    echo "$KNOWN_DEFER" | grep -qw "$d" || unexpected="$unexpected $d"
done
check "B4 미룬 것이 카탈로그가 선언한 것뿐이다" \
    "$([ -z "$unexpected" ] && echo 1 || echo 0)" \
    "$([ -z "$unexpected" ] && echo "미룸 [$defer] — 전부 linux_from:None" \
       || echo "선언 밖:$unexpected")"

# ════════════════════════════════════════════════════════════════════
# C. 치료
# ════════════════════════════════════════════════════════════════════
echo "── C. 치료 ──"

"$BIN" apply --plan "$PLAN" --yes --state-dir "$STATE" \
    --events "$OUT/apply.ndjson" > "$OUT/apply.log" 2>&1
rc=$?
# CA 도구가 없는 이미지에서는 `cert_store.remove` 하나가 거부되어 3(부분 실패)
# 이 정상이다. 그것 말고 실패한 것이 있으면 3 이라도 실패다.
# `grep -c` 는 0건일 때 "0" 을 찍고 종료 코드 1 을 낸다. `|| echo 0` 을 붙이면
# "0" 이 두 줄이 되어 `[` 가 정수로 못 읽는다.
other_fail="$(grep -c '^  실패 ' "$OUT/apply.log" 2>/dev/null)" || other_fail=0
[ -z "$CA_TOOL" ] && expect_rc=3 || expect_rc=1
[ -z "$CA_TOOL" ] && expect_fail=1 || expect_fail=0
check "C1 apply 가 완료한다" \
    "$([ $rc -eq $expect_rc ] && [ "$other_fail" -le "$expect_fail" ] && echo 1 || echo 0)" \
    "exit=$rc (기대 $expect_rc) · 실패한 Action ${other_fail}건"

bash "$HERE/capture-state.sh" > "$OUT/after.json"

# ── 없어져야 할 것 ──────────────────────────────────────────────────
#
# **cron 은 파일이 아니라 줄이다.** 계획의 대상이 `/etc/cron.d/remedy-lab:1`
# 이므로 사라져야 하는 것은 그 줄이고 파일은 남는다. 아래 C4 가 그것을 잰다 —
# 여기서 파일까지 없어지길 요구하면 **계획보다 많이 지우라고 요구하는 것**이 된다.
gone="/opt/remedy-lab/payload.so
/etc/xdg/autostart/remedy-lab-auto.desktop
/etc/systemd/system/remedy-lab.service
/etc/systemd/system/multi-user.target.wants/remedy-lab.service
$HOME/.config/google-chrome/Default/Extensions/remedylabremedylabremedylabremed"
[ -n "$CA_TOOL" ] && gone="$gone
/usr/local/share/ca-certificates/lab-ca.crt"

gone_bad=""; gone_n=0
while IFS= read -r p; do
    [ -z "$p" ] && continue
    gone_n=$((gone_n + 1))
    [ "$(present "$OUT/after.json" "$(printf '%s' "$p" | sed 's/[.[\*^$]/\\&/g')")" = "false" ] \
        || gone_bad="$gone_bad $(basename "$p")"
done <<EOF
$gone
EOF
check "C2 없어져야 할 것이 없어졌다" \
    "$([ -z "$gone_bad" ] && echo 1 || echo 0)" \
    "$([ -z "$gone_bad" ] && echo "남음 0건 / ${gone_n}자리" || echo "남음:$gone_bad")"

# 잴 수 없던 자리를 **이름으로 남긴다.** 통과 수에 섞으면 사라진다.
if [ -z "$CA_TOOL" ]; then
    check "C2b 신뢰 저장소에서 인증서를 뺀다" "-" \
        "이 이미지에 update-ca-certificates 가 없다 — 거부가 옳은 동작이다"
fi

# ── 남아야 할 것 (G3 · 불변식 P) ────────────────────────────────────
#
# **이 하네스의 존재 이유다.** 치료 도구가 계획서에 없는 것을 지웠다면
# 그게 바로 2차 사고다.
stay_bad=""
for p in "/opt/remedy-lab/REMEDY-LAB.marker" \
         "/opt/remedy-lab/keepme.conf" \
         "/opt/remedy-lab/lab.conf" \
         "/opt/remedy-lab/lab.json" \
         "/usr/local/share/ca-certificates/decoy-ca.crt" \
         "/etc/cron.d/innocent-cron" \
         "/usr/share/applications/remedy-lab.desktop" \
         "/etc/hosts" \
         "$HOME/.config/google-chrome/Default/Extensions/innocentinnocentinnocentinnoce" \
         "/home/bob/.config/autostart/remedy-lab-user.desktop"; do
    [ "$(present "$OUT/after.json" "$(printf '%s' "$p" | sed 's/[.[\*^$]/\\&/g')")" = "true" ] \
        || stay_bad="$stay_bad $(basename "$p")"
done
check "C3 남아야 할 것이 전부 남았다 (G3)" \
    "$([ -z "$stay_bad" ] && echo 1 || echo 0)" \
    "$([ -z "$stay_bad" ] && echo "사라짐 0건 / 10자리" || echo "사라짐:$stay_bad")"

# ── 줄·키 단위 Op 은 줄·키만 뺐는가 ────────────────────────────────
#
# 파일이 남았다는 것만으로는 부족하다. **통째로 비웠어도 파일은 남는다.**
line_bad=""
for spec in "conf-implant:0" "conf-normal-first:1" "conf-normal-last:1" \
            "json-implant:0"  "json-keep:1" \
            "hosts-lab:0"     "hosts-localhost:1" \
            "desktop-arg:0"   "desktop-exec:1" \
            "cron-implant:0"  "cron-innocent:1"; do
    lbl="${spec%%:*}"; want="${spec#*:}"
    got="$(linecount "$OUT/after.json" "$lbl")"; got="${got:-?}"
    if [ "$want" = "0" ]; then
        [ "$got" = "0" ] || line_bad="$line_bad $lbl(=$got,기대0)"
    else
        [ "$got" != "0" ] && [ "$got" != "?" ] || line_bad="$line_bad $lbl(=$got,기대≥1)"
    fi
done
check "C4 줄·키 단위 Op 이 그것만 뺐다" \
    "$([ -z "$line_bad" ] && echo 1 || echo 0)" \
    "$([ -z "$line_bad" ] && echo "어긋남 0건 / 11자리" || echo "어긋남:$line_bad")"

# ── 되돌릴 수 없는 Op ───────────────────────────────────────────────
#
# **치료 전에 돌고 있었는지를 함께 본다.** 뒤만 보면 애초에 뜨지 않은 경우가
# 통과가 된다 — "죽였다" 가 아니라 "잴 것이 없었다" 인데. 2026-09-03
# debian:12 에서 실제로 그렇게 헛통과했다(`pgrep` 이 없는 이미지였다).
nb="$(grep -o '"labproc": [0-9]*' "$OUT/before.json" | sed 's/.*: //')"
np="$(grep -o '"labproc": [0-9]*' "$OUT/after.json" | sed 's/.*: //')"
check "C5 프로세스가 죽었다" \
    "$([ "${nb:-0}" -ge 1 ] && [ "${np:-1}" = "0" ] && echo 1 || echo 0)" \
    "치료 전 ${nb:-?}개 → 뒤 ${np:-?}개$([ "${nb:-0}" -lt 1 ] && echo '  ← 잴 것이 없었다')"

# ════════════════════════════════════════════════════════════════════
# D. 격리 · 복원
# ════════════════════════════════════════════════════════════════════
echo "── D. 격리 · 복원 ──"

RUN="$(grep -o '"run_id"[[:space:]]*:[[:space:]]*"[^"]*"' "$PLAN" \
        | sed 's/.*"\([^"]*\)"$/\1/' | head -1)"
check "D1 run_id 를 알 수 있다" "$([ -n "$RUN" ] && echo 1 || echo 0)" "${RUN:-없음}"

# `--yes` 없이는 계획만 보인다 — 그것부터 확인한다.
"$BIN" restore --run "$RUN" --state-dir "$STATE" > "$OUT/restore-plan.log" 2>&1
rc=$?
check "D2 --yes 없이는 계획만 보인다" "$([ $rc -le 2 ] && echo 1 || echo 0)" "exit=$rc"

"$BIN" restore --run "$RUN" --state-dir "$STATE" --yes \
    --extract-to "$OUT/extracted" > "$OUT/restore.log" 2>&1
rc=$?
n_ex=$(find "$OUT/extracted" -type f 2>/dev/null | wc -l)
check "D3 격리물을 꺼낼 수 있다" \
    "$([ $rc -le 1 ] && [ "$n_ex" -gt 0 ] && echo 1 || echo 0)" \
    "exit=$rc · 꺼낸 파일 ${n_ex}개"

# **바이트가 같은 것이 돌아왔는가.** 격리는 되돌릴 수 있다는 약속이고,
# 그 약속은 해시가 같을 때만 참이다.
want_sha="$(sha "$OUT/before.json" '/opt/remedy-lab/payload\.so')"
got_sha=""
if [ -n "$want_sha" ]; then
    # **이름으로 찾지 않는다.** 꺼낸 자리의 이름이 원본과 같다는 보장이 없고,
    # 여기서 재려는 것은 이름이 아니라 **바이트가 같은 것이 돌아왔는가**다.
    got_sha="$(find "$OUT/extracted" -type f -exec sha256sum {} \; 2>/dev/null \
                 | cut -d' ' -f1 | grep -x "$want_sha" | head -1)"
fi
check "D4 꺼낸 것이 원본과 바이트가 같다" \
    "$([ -n "$want_sha" ] && [ "$want_sha" = "$got_sha" ] && echo 1 || echo 0)" \
    "$(printf '%.12s' "${want_sha:-없음}") vs $(printf '%.12s' "${got_sha:-없음}")"

# ── 제자리 복원 · 소유자 · 링크 (이슈 #172 · 엔진 1.27.0 부터) ──────
#
# 꺼내기는 바이트만 잰다. **제자리 복원은 누구의 것으로 돌아왔는가**까지 재야 한다 — root 로 되돌린 사용자의
# 4755 는 root 의 4755 다. 복원은 격리물을 쓰지 않으므로(소비하지 않는다) D7 이 같은 회차를 한 번 더 연다.
if [ "$JUDGE_NEW" = 1 ]; then
    "$BIN" restore --run "$RUN" --state-dir "$STATE" --yes > "$OUT/restore-inplace.log" 2>&1
    rc=$?
    n_back="$(grep -c '^  복원 \[' "$OUT/restore-inplace.log")"
    # CA 도구가 없는 이미지에서는 치료가 거부한 인증서(C1)의 격리 항목을 복원도 같은 까닭으로 거부해 3(부분
    # 실패)이 정상이다. 실패 줄이 그 한 항목 말고도 있으면 3 이라도 실패다. `grep -c` 는 0건이면 "0" 을 찍는다.
    d5_fail="$(grep '^  실패 \[' "$OUT/restore-inplace.log")"
    d5_nf="$(printf '%s' "$d5_fail" | grep -c '^')"
    d5_other="$(printf '%s' "$d5_fail" \
        | grep -vc '^  실패 \[e[0-9]*\] /usr/local/share/ca-certificates/lab-ca\.crt ')"
    [ -z "$CA_TOOL" ] && d5_rc=3 || d5_rc=0
    [ -z "$CA_TOOL" ] && d5_nf_want=1 || d5_nf_want=0
    check_new "D5 제자리로 복원한다" \
        "$([ $rc -eq $d5_rc ] && [ "$d5_nf" -eq "$d5_nf_want" ] && [ "$d5_other" -eq 0 ] && echo 1 || echo 0)" \
        "exit=$rc (기대 $d5_rc) · 복원 줄 ${n_back:-?}건 · 실패 줄 ${d5_nf}건$(
           [ "$d5_other" -gt 0 ] && echo " (인증서 밖 ${d5_other}건)")"
    # 잴 수 없던 자리를 이름으로 남긴다(C2b 와 같다).
    if [ -z "$CA_TOOL" ]; then
        check_new "D5b 신뢰 저장소에 인증서를 되돌린다" "-" \
            "이 이미지에 update-ca-certificates 가 없다 — 치료처럼 복원도 거부가 옳은 동작이다"
    fi
    bash "$HERE/capture-state.sh" > "$OUT/restored.json"

    # 치료가 지운 자리(치료 전 있음 → 치료 뒤 없음)마다 치료 전과 복원 뒤의 줄이 같은가. 줄은 capture-state 가
    # 담은 전부다 — 종류 · 크기 · mode · 소유자 · 해시 · 링크가 가리키는 곳.
    TOOL=/home/alice/bin/remedy-lab-tool
    MUST="$TOOL /opt/remedy-lab/www.dat $BU/systemd/user/remedy-lab-user.service
$BU/systemd/user/remedy-lab-user.timer $BU/systemd/user/default.target.wants/remedy-lab-user.service"
    removed=""; d6_bad=""; d6_n=0
    for p in $(grep -o '^    { "path": "[^"]*", "present": true' "$OUT/before.json" \
                 | sed 's/^    { "path": "\([^"]*\)".*/\1/'); do
        pe="$(printf '%s' "$p" | sed 's/[.[\*^$]/\\&/g')"
        [ "$(present "$OUT/after.json" "$pe")" = "false" ] || continue
        removed="$removed $p"
        d6_n=$((d6_n + 1))
        b="$(obj "$OUT/before.json" "$p")"; r="$(obj "$OUT/restored.json" "$p")"
        [ "$b" = "$r" ] && continue
        if [ "$(present "$OUT/restored.json" "$pe")" != "true" ]; then
            d6_bad="$d6_bad $(lbl "$p")(복원 안 됨)"; continue
        fi
        diffs=""
        for f in kind owner mode sha256 target; do
            fb="$(fld "$b" "$f")"; fr="$(fld "$r" "$f")"
            [ "$fb" = "$fr" ] || diffs="$diffs $f $(printf '%.12s' "${fb:-없음}")→$(printf '%.12s' "${fr:-없음}")"
        done
        d6_bad="$d6_bad $(lbl "$p")(${diffs# })"
    done
    untreated=""
    for m in $MUST; do
        case " $removed " in *" $m "*) ;; *) untreated="$untreated $(lbl "$m")" ;; esac
    done
    tm_b="$(fld "$(obj "$OUT/before.json" "$TOOL")" mode)"
    tm_r="$(fld "$(obj "$OUT/restored.json" "$TOOL")" mode)"
    check_new "D6 복원이 소유자 · mode · 링크까지 되돌린다" \
        "$([ -z "$d6_bad" ] && [ -z "$untreated" ] && [ "$tm_b" = 4755 ] && [ "$tm_r" = 4755 ] \
           && echo 1 || echo 0)" \
        "$([ -z "$d6_bad" ] && echo "어긋남 0건 / ${d6_n}자리" || echo "어긋남:$d6_bad")$(
           [ -n "$untreated" ] && echo " · 치료되지 않음:$untreated") · 도구 mode ${tm_b:-없음}→${tm_r:-없음}"

    # 격리된 파일의 부모를 사용자가 바꿔 놓은 링크로 — root 의 자리를 가리킨다. 제자리 복원이 그 링크를 따라
    # 쓰면 root 가 root 의 자리에 사용자가 고른 이름 · 바이트 · mode 를 쓴다. 그 항목만 연다(`--entry`).
    D7_ROOT=/etc/remedy-lab-d7
    eid="$(sed -n "s|^  \[\([^]]*\)\] $TOOL\$|\1|p" "$OUT/restore-plan.log" | head -1)"
    if [ -z "$eid" ] || [ ! -d /home/alice/bin ] || [ -L /home/alice/bin ]; then
        check_new "D7 링크로 바뀐 부모 너머에 쓰지 않는다" 0 \
            "잴 수 없다 — 격리 항목 ${eid:-없음} · /home/alice/bin 이 폴더가 아니다"
    else
        mv /home/alice/bin /home/alice/bin.d7
        ln -s "$D7_ROOT" /home/alice/bin
        chown -h alice:alice /home/alice/bin
        "$BIN" restore --run "$RUN" --state-dir "$STATE" --yes --entry "$eid" \
            > "$OUT/restore-link.log" 2>&1
        rc=$?
        wrote="$(find "$D7_ROOT" -mindepth 1 2>/dev/null | wc -l)"
        what="$(find "$D7_ROOT" -mindepth 1 -exec stat -c '%n %u:%g %a' {} \; 2>/dev/null | tr '\n' ' ')"
        link_ok=0
        [ -L /home/alice/bin ] && [ "$(readlink /home/alice/bin)" = "$D7_ROOT" ] \
            && [ "$(stat -c %u /home/alice/bin)" = 4242 ] && link_ok=1
        rm -f /home/alice/bin && mv /home/alice/bin.d7 /home/alice/bin
        check_new "D7 링크로 바뀐 부모 너머에 쓰지 않는다" \
            "$([ $rc -eq 5 ] && [ "$wrote" = 0 ] && [ "$link_ok" = 1 ] && echo 1 || echo 0)" \
            "exit=$rc (기대 5) · 항목 $eid · 링크가 가리킨 자리에 생긴 것 ${wrote}개${what:+ [${what% }]} · 링크 그대로 $([ "$link_ok" = 1 ] && echo 예 || echo 아니오)"
    fi

    # 꺼낸 사본은 꺼낸 계정의 것이고 setuid · setgid 가 없는가. 담아 둔 소유자는 번호라 다른 기계에서는 같은 번호의
    # 다른 계정이고, setuid 를 단 사본은 꺼낸 폴더에 그 소유자의 권한으로 도는 실행 파일이 된다. **D3 의 사본으로 재지
    # 않는다** — 그 자리(`--out`)는 호스트가 붙인 폴더라, WSL 에서 Windows 드라이브(9p)를 붙이면 모든 파일이 1000:1000 ·
    # 777 로 보인다(2026-11-27 잼). 도구 항목 하나만 컨테이너 안의 빈 폴더로 한 번 더 꺼내 거기서 잰다(D7 처럼 같은 회차를
    # 다시 연다). 파일 권능(`security.capability`)은 이 이미지에 `setcap` 이 없어 여기서 재지 않는다 — 코어의 단위 시험
    # `extracting_drops_the_setid_bits_the_file_capability_and_the_owner` 가 잰다.
    me="$(id -u):$(id -g)"
    tb="$(obj "$OUT/before.json" "$TOOL")"
    t_sha="$(fld "$tb" sha256)"
    ex=""; ex_own=""; ex_mode=""; rc8=-
    if [ -n "$eid" ] && [ -n "$t_sha" ]; then
        D8_DIR="$(mktemp -d /tmp/remedy-lab-d8.XXXXXX)"
        "$BIN" restore --run "$RUN" --state-dir "$STATE" --yes --entry "$eid" --extract-to "$D8_DIR" \
            > "$OUT/restore-extract-tool.log" 2>&1
        rc8=$?
        ex="$(find "$D8_DIR" -type f -exec sha256sum {} + 2>/dev/null | grep "^$t_sha " | head -1 | cut -c67-)"
        [ -n "$ex" ] && ex_own="$(stat -c %u:%g "$ex")" && ex_mode="$(stat -c %a "$ex")"
        rm -rf "$D8_DIR"
    fi
    check_new "D8 꺼낸 사본은 꺼낸 계정의 것이고 setuid · setgid 가 없다" \
        "$([ "$rc8" = 0 ] && [ -n "$ex" ] && [ "$ex_own" = "$me" ] && [ $((0$ex_mode & 06000)) -eq 0 ] \
           && echo 1 || echo 0)" \
        "exit=$rc8 · 항목 ${eid:-없음} · $([ -z "$ex" ] && echo "도구 사본 없음" || echo "도구 사본 ${ex_own} · mode ${ex_mode}") — 기대 꺼낸 계정 $me · setuid · setgid 없음 (치료 전 $(fld "$tb" owner) · $(fld "$tb" mode))"
else
    skip_new "D5" "D6" "D7" "D8"
fi

# ════════════════════════════════════════════════════════════════════
# E. 저널
# ════════════════════════════════════════════════════════════════════
echo "── E. 저널 ──"

# 저널은 `state-dir/journal/<run>.jsonl` 이다. `--events` 로 따로 받은 것은
# **같은 것이 아니다** — 그쪽은 진행 사건이고 저널은 무엇을 했는지의 기록이다.
JRN="$(find "$STATE" -name '*.jsonl' 2>/dev/null | head -1)"
nl=0; [ -n "$JRN" ] && nl=$(wc -l < "$JRN")
check "E1 저널이 남는다" "$([ -n "$JRN" ] && [ "$nl" -gt 0 ] && echo 1 || echo 0)" \
    "${nl}줄"

# 2026-09-02 에 넣은 필드. **어떤 바이너리가 이 기계를 고쳤는지**를 남긴다.
si="$(grep -o '"self_integrity"[[:space:]]*:[[:space:]]*"[a-z]*"' "$JRN" 2>/dev/null \
        | sed 's/.*"\([a-z]*\)"$/\1/' | head -1)"
check "E2 저널이 자기무결성을 적는다" "$([ -n "$si" ] && echo 1 || echo 0)" \
    "self_integrity=${si:-없음}"

# ════════════════════════════════════════════════════════════════════
# F. 서명 없이 전부 돌았다
# ════════════════════════════════════════════════════════════════════
echo "── F. 서명 ──"

# Linux 에는 Authenticode 가 없다. 그래도 **탐지·계획·보고·치료가 전부
# 돌아야 한다** — 서명은 공식 배포의 절차이지 기능의 조건이 아니다.
# 알림 문구는 1.1.1 에서 Windows 와 같은 꼴(코드서명 확인이 없어 …)로 바뀌었다 — 옛 꼴과 새 꼴을
# 다 센다. 하나만 세면 문구가 바뀐 판에서 F1 이 실패하고, 그것이 F2 까지 끌어내린다.
adv="$("$BIN" --version 2>&1 | grep -c '자기무결성\|integrity\|코드서명\|code-signing')"
check "F1 서명이 없다는 사실을 매 실행에서 말한다" \
    "$([ "$adv" -ge 1 ] && echo 1 || echo 0)" "알림 ${adv}건"
# #172 칸의 실패는 엔진 결함을 잰 것이지 서명이 막은 것이 아니다 — 따로 센다(머리말).
old_fail=$((FAIL - FAIL_NEW))
check "F2 그것이 기능을 막지 않았다" \
    "$([ "$old_fail" -eq 0 ] && echo 1 || echo 0)" \
    "$([ "$old_fail" -eq 0 ] && echo "여기까지 실패 0건" || echo "앞선 실패 ${old_fail}건")$(
       [ "$FAIL_NEW" -gt 0 ] && echo " · #172 칸의 실패 ${FAIL_NEW}건은 따로 센다")"

# ── 판정 ────────────────────────────────────────────────────────────
echo
echo "통과 $PASS · 실패 $FAIL · 못잼 $UNMEASURED  (전체 $((PASS + FAIL + UNMEASURED)))$(
     [ "$SKIPPED" -gt 0 ] && echo " · 건너뜀 $SKIPPED — 엔진 $ENGINE < $NEW_SINCE")"
[ "$UNMEASURED" -gt 0 ] && echo "  ** 못 잰 것은 통과가 아니다. 위 노란 줄이 무엇을 못 봤는지 말한다."

# Windows 쪽과 같은 모양으로 남기되 `ok` 가 셋째 값을 갖는다 — 못 잰 것은
# `null` 이다. `false` 로 적으면 두 플랫폼의 결과를 함께 세는 쪽에서 실패로
# 읽히고, `true` 로 적으면 잰 적 없는 것이 통과가 된다.
#
# 이름과 detail 은 **쓰는 자리에서** JSON 문자열로 이스케이프한다(`capture-state.sh` 의 `esc` 와 같다). detail 에는
# 레코드의 값이 따옴표째 실린다 — A5 의 `principal="bob"` 이 이 파일을 JSON 으로 읽히지 않게 했다(2026-11-27).
# 칸마다 막지 않고 여기서 막아야 앞으로 더할 칸까지 덮는다.
jesc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
{
    printf '[\n'
    first=1
    while IFS=$'\t' read -r n o d; do
        [ "$first" -eq 1 ] || printf ',\n'
        first=0
        case "$o" in
            1) ob=true ;;
            -) ob=null ;;
            *) ob=false ;;
        esac
        printf '  { "name": "%s", "ok": %s, "detail": "%s" }' "$(jesc "$n")" "$ob" "$(jesc "$d")"
    done < "$OUT/.checks"
    printf '\n]\n'
} > "$RESULT"
rm -f "$OUT/.checks"
echo "결과: $RESULT"

# 실험대를 치운다. 컨테이너는 어차피 사라지지만, --force 로 돌린 경우가 있다.
bash "$HERE/new-fixtures.sh" --clean $FORCE > /dev/null 2>&1

[ "$FAIL" -eq 0 ] || exit 1
exit 0
