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
# # 쓰는 법 (컨테이너 안)
#
#     verify-linux.sh --bin /w/target-linux/release/remedy --out /w/out
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

echo
echo "═══ Linux 실기기 검증 ═══"
"$BIN" --version 2>&1 | sed 's/^/  /'
echo "  이미지  $( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-불명}" )"
echo "  PID 1   $(cat /proc/1/comm 2>/dev/null || echo 불명)"
echo

# ── 픽스처 ──────────────────────────────────────────────────────────
bash "$HERE/new-fixtures.sh" --clean $FORCE > /dev/null 2>&1
bash "$HERE/new-fixtures.sh" $FORCE | sed 's/^/  /' || { echo "픽스처 생성 실패"; exit 1; }
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
bad=""
for d in "REMEDY-LAB.marker" "keepme.conf" "decoy-ca.crt" "innocent-cron" \
         "innocentinnocentinnocentinnoce"; do
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
         "$HOME/.config/google-chrome/Default/Extensions/innocentinnocentinnocentinnoce"; do
    [ "$(present "$OUT/after.json" "$(printf '%s' "$p" | sed 's/[.[\*^$]/\\&/g')")" = "true" ] \
        || stay_bad="$stay_bad $(basename "$p")"
done
check "C3 남아야 할 것이 전부 남았다 (G3)" \
    "$([ -z "$stay_bad" ] && echo 1 || echo 0)" \
    "$([ -z "$stay_bad" ] && echo "사라짐 0건 / 9자리" || echo "사라짐:$stay_bad")"

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
check "F2 그것이 기능을 막지 않았다" \
    "$([ "$FAIL" -eq 0 ] && echo 1 || echo 0)" \
    "$([ "$FAIL" -eq 0 ] && echo "여기까지 실패 0건" || echo "앞선 실패 ${FAIL}건")"

# ── 판정 ────────────────────────────────────────────────────────────
echo
echo "통과 $PASS · 실패 $FAIL · 못잼 $UNMEASURED  (전체 $((PASS + FAIL + UNMEASURED)))"
[ "$UNMEASURED" -gt 0 ] && echo "  ** 못 잰 것은 통과가 아니다. 위 노란 줄이 무엇을 못 봤는지 말한다."

# Windows 쪽과 같은 모양으로 남기되 `ok` 가 셋째 값을 갖는다 — 못 잰 것은
# `null` 이다. `false` 로 적으면 두 플랫폼의 결과를 함께 세는 쪽에서 실패로
# 읽히고, `true` 로 적으면 잰 적 없는 것이 통과가 된다.
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
        printf '  { "name": "%s", "ok": %s, "detail": "%s" }' "$n" "$ob" "$d"
    done < "$OUT/.checks"
    printf '\n]\n'
} > "$RESULT"
rm -f "$OUT/.checks"
echo "결과: $RESULT"

# 실험대를 치운다. 컨테이너는 어차피 사라지지만, --force 로 돌린 경우가 있다.
bash "$HERE/new-fixtures.sh" --clean $FORCE > /dev/null 2>&1

[ "$FAIL" -eq 0 ] || exit 1
exit 0
