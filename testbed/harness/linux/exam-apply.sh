#!/bin/bash
# 채점 5 — 치료가 **실기기에서 실제로 됐는가** (Linux).
#
# Windows 쪽 `host/Invoke-ExamApply.ps1` 의 짝이고 판정 규칙이 같다.
#
# # 왜 필요한가
#
# `cargo xtask exam` 의 네 판정은 전부 **계획까지만 잰다.** 계획이 정상으로
# 서고 실행에서 거부되거나 조용히 아무것도 하지 않는 Action 은 어디에도
# 걸리지 않는다. 2026-09-05 하루에 Windows 에서 그 틈으로 결함 다섯이
# 지나갔고, 다섯 다 네 판정이 초록이었다.
#
# # 무엇을 판정하는가
#
# 두 가지를 따로 잰다.
#
# **1. 범위 안 — 사전 등록 자료가 지목한 성질이 이루어졌는가.**
#
#   | Op 의 종류 | 무엇을 보는가 |
#   |---|---|
#   | 없애는 Op | 치료 뒤 그 자리가 **없어야 한다** |
#   | 고치는 Op + `line=` 이 있다 | 그 **줄만** 빠지고 나머지 줄은 그대로여야 한다 |
#   | 고치는 Op + `line=` 이 없다 | 청정 기준과 같아야 한다 |
#
#   **청정 기준으로 범위 안을 재지 않는 이유가 있다.** 픽스처는 위협만 세우지
#   않는다 — 미끼(정상으로 보이는 항목)도 함께 세우고, 그것은 치료 뒤에도 남는
#   것이 맞다. `tls-intercept` 의 `/etc/hosts` 가 그렇다: 픽스처가 사내 서버 줄
#   하나를 더하고 컨테이너 자신의 호스트명 줄을 덮어쓴다. 청정 파일과 견주면
#   치료가 정확히 두 줄을 뺐는데도 **영원히 불합격**이 된다 (2026-09-05 실측).
#
# **2. 범위 밖 — 치료가 건드리지 말아야 할 것을 건드렸는가.**
#
#   여기서는 청정 기준이 맞다. 치료 전에는 청정과 같았는데 치료 뒤에 달라진
#   것이 **부수 피해**다.
#
# # 어디를 보는가
#
# 위협의 **사전 등록 자료**(`expected-ops.txt`)가 정한다. 응시자의 `plan.json`
# 에서 뽑으면 검증자가 피검증자를 믿는 것이고, 아무것도 계획하지 않은 답안이
# 아무 데도 안 보이는 채로 통과한다.
#
# **대상이 남아야 하는지 없어져야 하는지**는 `machine/ops.json` 의
# `edits_in_place` 가 말한다 — 출처는 `Op::edits_in_place` 하나이고 두 하네스가
# 그것을 함께 읽는다. 손으로 적으면 갈라진다(실제로 그랬다).
#
# ## 아는 공백 — cron 대상 모양을 모른다 (2026-09-21)
#
# `edits_in_place` 가 거짓이면 **대상 경로의 파일이 사라졌는가**로 본다. 그런데
# cron 레코드의 대상은 `<파일>:<줄번호>` 라(`cron.rs`) 그런 파일이 없고, 그
# 자리는 "감염 상태에 파일이 없다" 로 **못 잰 곳**이 된다. Windows 쪽은 예약
# 작업 이름을 대상으로 받아 저쪽 채점기가 그것을 안다.
#
# `ssh-backdoor` 를 만들며 드러났다. 그 위협은 cron 파일이 통째로 검체의 것이라
# **파일 격리가 치료로도 더 맞아서** 설계를 바꿔 피했다. 하지만 *"정상 cron
# 파일에 검체 줄 하나가 끼어든"* 위협을 만들면 여기서 막힌다 — 그때는 채점기가
# `<파일>:<줄번호>` 를 갈라 그 줄이 사라졌는지 보도록 고쳐야 한다.
#
# # 쓰는 법 — 컨테이너 안에서
#
#     exam-apply.sh --threat ldso-preload --bin /usr/local/bin/remedy --out /out
#
# 호스트에서는 `invoke-exam-apply.sh` 가 이것을 띄운다.

set -u
# 이 스크립트는 한국어 문구를 읽는다. 기본 언어는 영어다 (2026-09-06).
export REMEDY_LANG=ko

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
THREAT=""
BIN=""
OUT=""
PLUGIN=""
ATTENDED=0

while [ $# -gt 0 ]; do
    case "$1" in
        --threat)   THREAT="${2:-}"; shift 2 ;;
        --bin)      BIN="${2:-}"; shift 2 ;;
        --out)      OUT="${2:-}"; shift 2 ;;
        --plugin)   PLUGIN="${2:-}"; shift 2 ;;
        --attended) ATTENDED=1; shift ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done

case "$THREAT" in
    ldso-preload|tls-intercept|c2-beacon|xmr-miner|ssh-backdoor|selfcopy-worm|npm-posthook|hexcfg-loader) ;;
    *) echo "--threat ldso-preload | tls-intercept | c2-beacon | xmr-miner | ssh-backdoor | selfcopy-worm | npm-posthook | hexcfg-loader"; exit 2 ;;
esac
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin 이 실행 파일이 아니다: $BIN"; exit 2; }
[ -n "$OUT" ] || { echo "--out 이 필요하다"; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "root 로 돌아야 한다."; exit 1; }
# 대화형 회차는 pty 를 만들어야 한다. 없으면 코어가 "승인할 사람이 없습니다" 로
# 거절하고, 그 거절은 승인 경로를 **재지 않은 채 통과**한다.
[ "$ATTENDED" -eq 0 ] || command -v script > /dev/null 2>&1 || {
    echo "--attended 는 script(util-linux)가 필요하다. 이 이미지에는 없다."
    exit 1
}

# 컨테이너 밖에서 돌면 이 기계를 감염시킨다. 픽스처 스크립트도 같은 확인을 한다.
[ -f /.dockerenv ] || grep -qa 'docker\|containerd' /proc/1/cgroup 2>/dev/null || {
    echo "컨테이너가 아니다. 이 스크립트는 /etc/hosts 와 /etc/ld.so.conf.d 를 고친다."
    exit 1
}

THREAT_DIR="$REPO/testbed/ai-exam/threats/$THREAT"
EXPECTED="$THREAT_DIR/expected-ops.txt"
OPS_JSON="$REPO/docs/plugin-guide/machine/ops.json"
[ -n "$PLUGIN" ] || PLUGIN="$THREAT_DIR/reference-plugin/plugin.yaml"
for f in "$EXPECTED" "$OPS_JSON" "$PLUGIN"; do
    [ -f "$f" ] || { echo "없다: $f"; exit 1; }
done

mkdir -p "$OUT"
WORK="$(mktemp -d)"
mkdir -p "$WORK/lines" "$WORK/args" "$WORK/keys" "$WORK/snap/clean" "$WORK/snap/infected" "$WORK/snap/treated" "$WORK/snap/refused"

# ─────────────────────────────────────────── 관측 범위

# 대상이 남아야 하는 Op 의 전수. **`match` 에 와일드카드가 없어 컴파일러가
# 분류를 강제하므로 이 목록에 빈칸이 생길 수 없다** (`Op::edits_in_place`).
#
# 객체 하나를 통째로 모았다가 닫는 줄에서 판정한다 — 필드 순서에 기대지 않는다.
awk '
    /^    \{/            { e = ""; id = "" }
    /"edits_in_place":/  { e = (index($0, "true") ? 1 : 0) }
    /"id":/              { id = $0; sub(/.*"id": *"/, "", id); sub(/".*/, "", id) }
    /^    \}/            { if (id != "" && e == 1) print id }
' "$OPS_JSON" > "$WORK/edits-in-place.txt"
[ -s "$WORK/edits-in-place.txt" ] || {
    echo "Op 표에서 아무것도 읽지 못했다 — 그 상태의 판정은 전부 거짓이다: $OPS_JSON"
    exit 1
}

# `expected-ops.txt` 한 줄은 `<op> <대상>` 이고 뒤에 ` :: <match>` 가 붙을 수
# 있다. 같은 대상에 줄이 여럿 걸릴 수 있어(hosts 둘) **대상별로 모은다.**
#
# `line=` 의 내용에는 탭이 들어 있다. TSV 에 담을 수 없으므로 대상마다 파일
# 하나(`lines/<n>`)에 한 줄씩 적는다.
: > "$WORK/scope.tsv"
: > "$WORK/trace.tsv"
TRACE_HOST="$(hostname) $(uname -sr)"
: > "$WORK/unknown-match.txt"
idx=0
while IFS= read -r line; do
    case "$line" in ""|'#'*) continue ;; esac
    body="${line%% :: *}"
    match=""
    [ "$body" != "$line" ] && match="${line#* :: }"
    op="${body%% *}"
    target="${body#* }"
    [ -n "$target" ] && [ "$target" != "-" ] || continue

    # 이미 본 대상이면 줄만 더한다.
    n="$(awk -F'\t' -v t="$target" '$2 == t { print $4; exit }' "$WORK/scope.tsv")"
    if [ -z "$n" ]; then
        idx=$((idx + 1)); n=$idx
        kind=gone
        grep -qxF "$op" "$WORK/edits-in-place.txt" && kind=edits
        printf '%s\t%s\t%s\t%s\n' "$op" "$target" "$kind" "$n" >> "$WORK/scope.tsv"
    fi
    # `line_no=8, line=<내용>` 에서 내용만. 탭이 들어 있으므로 자르지 않는다.
    case "$match" in
        # **구조적 설정에서 빠져야 하는 키 하나** (2026-09-22). 점으로 이은
        # 자리표다(`scripts.postinstall`). `line=` 보다 먼저 본다 — 키 이름에
        # `line=` 이 들어 있어도 키 검사로 가야 한다.
        *key_path=*) printf '%s\n' "${match#*key_path=}" > "$WORK/keys/$n" ;;
        *line=*) printf '%s\n' "${match#*line=}" >> "$WORK/lines/$n" ;;
        # 바로가기가 **떼어야 할 인자**. 수집기가 필드 코드를 이미 뺀 값이라
        # 그대로 "없어져야 할 것" 이다 (`write::split_exec`).
        *args=*) printf '%s\n' "${match#*args=}" > "$WORK/args/$n" ;;
    esac
    # **모르는 매치를 조용히 넘기지 않는다.**
    #
    # 재료가 성질을 지목했는데 하네스가 그것을 볼 줄 모르면, 그 자리는
    # "청정 기준과 같아야 한다" 로 떨어지거나 `판정 불가` 가 된다. 둘 다
    # 재지 않은 것을 재지 않았다고 말하지 못한다.
    #
    # **2026-09-22 에 이 자리의 비대칭이 닫혔다.** 그전까지 이 하네스는
    # `line=` 과 `args=` 만 보고 `key_path=` 를 몰랐고(Windows 는 그 반대였다),
    # 그래서 구조적 설정의 키 하나를 재는 위협은 리눅스에서 미결로 끝났다 —
    # `proxy-dns-hijack`(`line=`)·`shortcut-hijack`(`args=`) 이 Windows 쪽에서
    # 같은 모양으로 닫은 그 자리다. 이제 **네 매치 종류를 두 하네스가 모두
    # 본다.**
    if [ -n "$match" ]; then
        k="$(awk -F'\t' -v t="$target" '$2 == t { print $3; exit }' "$WORK/scope.tsv")"
        case "$k:$match" in
            edits:*key_path=*) ;;
            edits:*line=*) ;;
            edits:*args=*) ;;
            edits:*) printf '%s  (매치 %s)\n' "$target" "$match" >> "$WORK/unknown-match.txt" ;;
        esac
    fi
done < "$EXPECTED"
[ -s "$WORK/scope.tsv" ] || { echo "관측 범위가 비었다 — 그 상태의 '변화 없음' 은 거짓이다"; exit 1; }

# 훑을 디렉터리 — **없애는 Op 의 대상만 부모를 훑는다.**
#
# 고치는 Op 의 대상은 남는 것이 이미 정해져 있고, 그 부모를 훑으면 `/etc/hosts`
# 때문에 `/etc` 를 통째로 보게 된다. 없애는 Op 쪽은 반대다 — 옆엣것이 함께
# 지워졌는지가 정확히 그 부모에서 보인다.
: > "$WORK/dirs.txt"
while IFS=$'\t' read -r op target kind _n; do
    [ "$kind" = gone ] || continue
    case "$op" in
        dir.*) printf '%s\n' "$target" >> "$WORK/dirs.txt" ;;
        *)     printf '%s\n' "$(dirname "$target")" >> "$WORK/dirs.txt" ;;
    esac
done < "$WORK/scope.tsv"
sort -u "$WORK/dirs.txt" -o "$WORK/dirs.txt"

# ── 남아야 하는 자리 ────────────────────────────────────────────────
#
# `expected-ops.txt` 가 **치료가 해야 할 일**이라면 `must-remain.txt` 는
# **치료가 건드리면 안 되는 것**이다. 픽스처가 감염과 함께 세운 정상
# 소프트웨어이고, 청정 기계에는 없다.
#
# **청정이 아니라 감염과 견준다.** 청정에 없는 자리라 청정과 견주면 영영
# `판정 불가` 이고, 치료가 지워 버리면 청정도 치료도 `absent` 이라 차분에
# 아무것도 안 나타난다 — 그것이 2026-09-06 감사가 찾은 구멍이다.
: > "$WORK/must-remain.txt"
MUST_FILE="$THREAT_DIR/must-remain.txt"
[ -f "$MUST_FILE" ] || { echo "$MUST_FILE 가 없다 — 적을 것이 없으면 빈 파일로 둘 것"; exit 1; }
while IFS= read -r line; do
    case "$line" in ""|'#'*) continue ;; esac
    printf '%s\n' "$line" >> "$WORK/must-remain.txt"
done < "$MUST_FILE"

echo "[*] 관측 범위 — $THREAT 의 expected-ops.txt 에서"
while IFS=$'\t' read -r op target kind n; do
    nl=0; [ -f "$WORK/lines/$n" ] && nl="$(wc -l < "$WORK/lines/$n")"
    printf '    %-6s %s  (%s' "$kind" "$target" "$op"
    [ "$nl" -gt 0 ] && printf ' · 줄 %s개' "$nl"
    printf ')\n'
done < "$WORK/scope.tsv"
while read -r d; do [ -n "$d" ] && printf '    훑음   %s\n' "$d"; done < "$WORK/dirs.txt"
while read -r m; do [ -n "$m" ] && printf '    남아야 %s\n' "$m"; done < "$WORK/must-remain.txt"

# ─────────────────────────────────────────── 관측

# 경로 하나의 값. **없는 것도 값이다** — 빠뜨리는 것과 없는 것은 다르다.
value_of() {
    local p="$1"
    if [ -L "$p" ]; then printf 'link %s' "$(readlink "$p")"
    elif [ -f "$p" ]; then printf 'file %s %s' "$(sha256sum "$p" | cut -d' ' -f1)" "$(stat -c %a "$p")"
    elif [ -d "$p" ]; then printf 'dir %s' "$(stat -c %a "$p")"
    else printf 'absent'
    fi
}

# 한 시점의 상태. `<경로>\t<값>` 을 정렬해 적고, 줄 검사가 걸린 파일은 **내용
# 자체를** 함께 뜬다 (해시만으로는 어느 줄이 달라졌는지 말할 수 없다).
#
# **remedy 를 부르지 않는다** — 검증자가 피검증자를 신뢰하면 검증이 아니다.
# `stat` · `sha256sum` · `readlink` 만 쓴다.
capture() {
    local stage="$1" p n
    {
        while IFS=$'\t' read -r _op target _kind n; do
            printf '%s\t%s\n' "$target" "$(value_of "$target")"
            { [ -f "$WORK/lines/$n" ] || [ -f "$WORK/args/$n" ] || [ -f "$WORK/keys/$n" ]; } \
                && [ -f "$target" ] && cp "$target" "$WORK/snap/$stage/$n"
        done < "$WORK/scope.tsv"
        while read -r d; do
            [ -n "$d" ] && [ -d "$d" ] || continue
            find "$d" -mindepth 1 2>/dev/null | while read -r p; do
                printf '%s\t%s\n' "$p" "$(value_of "$p")"
            done
        done < "$WORK/dirs.txt"
        while read -r m; do
            [ -n "$m" ] && printf '%s\t%s\n' "$m" "$(value_of "$m")"
        done < "$WORK/must-remain.txt"
    } | sort -u > "$OUT/state-$stage.tsv"

    # **그 회차의 흔적.** 증거는 손으로 쓸 수 있는 JSON 이고 게이트는 그것을
    # 믿는다. 완전히 막을 수는 없다 — 하네스도 우리 코드다. 목표는 "손으로 못
    # 쓰게" 가 아니라 **"손으로 쓴 것이 티가 나게"** 다. 기계만 낼 수 있고
    # 서로 아귀가 맞아야 하는 값을 함께 적는다.
    printf '%s\t%s\t%s\t%s\n' \
        "$stage" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$(sha256sum "$OUT/state-$stage.tsv" | cut -d' ' -f1)" \
        "$(wc -l < "$OUT/state-$stage.tsv")" >> "$WORK/trace.tsv"
}

cleanup() {
    echo
    echo "[*] 정리"
    bash "$HERE/new-threat-fixtures.sh" --threat "$THREAT" --clean > /dev/null 2>&1 \
        && echo "    픽스처 정리" || echo "    ** 픽스처 정리 실패 — 컨테이너를 버릴 것"
    rm -rf "$WORK"
}
trap cleanup EXIT

echo
echo "[*] 1/3 청정 기준"
capture clean
echo "    항목 $(wc -l < "$OUT/state-clean.tsv")건"

echo "[*] 감염: $THREAT"
bash "$HERE/new-threat-fixtures.sh" --threat "$THREAT" > "$OUT/fixtures.log" 2>&1 \
    || { echo "픽스처를 세우지 못했다 — $OUT/fixtures.log"; exit 1; }
echo "    픽스처 세움"

echo "[*] 2/3 감염 상태"
capture infected
echo "    항목 $(wc -l < "$OUT/state-infected.tsv")건"

# 산출물은 **관측 범위 밖**에 둔다. 격리 컨테이너와 저널이 관측에 섞이면
# 우리 흔적을 걸러 내는 목록이 또 필요해진다.
APPROVED=0
REFUSAL_OK=""
if [ "$ATTENDED" -eq 1 ]; then
    # **먼저 거부해 본다.** 승인 흐름은 두 갈래이고 '예' 쪽만 재면 절반이다 —
    # 승인하지 않았는데 무엇인가 바뀌는 것이 이 도구가 낼 수 있는 최악의
    # 실패다. 리눅스에서 이 갈래는 한 번도 돈 적이 없다.
    echo "[*] 승인 거부를 먼저 잰다"
    printf 'no\n' | script -qec \
        "$BIN run --plugin $PLUGIN --out-dir $WORK/refuse --state-dir $WORK/refuse-state" \
        /dev/null > "$OUT/refuse.log" 2>&1
    capture refused
    if ! cmp -s "$OUT/state-infected.tsv" "$OUT/state-refused.tsv"; then
        REFUSAL_OK=no
        echo "    ** 승인하지 않았는데 기계가 바뀌었다"
    elif tr -d '\r' < "$OUT/refuse.log" | grep -q "아무것도 하지 않았습니다"; then
        REFUSAL_OK=yes
        echo "    거부하니 아무것도 하지 않았고 기계도 그대로다"
    else
        REFUSAL_OK=unknown
        echo "    ** 기계는 그대로인데 '아무것도 하지 않았습니다' 를 말하지 않았다"
    fi

    echo "[*] 치료: run (대화형 · 하네스가 승인한다)"
    # **`--yes` 를 주지 않는다.** 그것은 "화면 앞에 사람이 없다" 는 선언이고,
    # 그러면 계획기가 `cert_store.remove` 를 빼 버린다.
    #
    # 그런데 코어는 stdin 이 **터미널인지**까지 본다 (`approved()` 의
    # `is_terminal()`). 파이프로 답을 밀어 넣으면 "승인할 사람이 없습니다" 로
    # 거절되고, 그 거절은 승인 경로를 **재지 않은 채 통과**한다. 그래서
    # `script` 로 pty 를 만들어 그 안에서 돌린다 — Windows 쪽
    # `Approve-Interactive.ps1` 이 콘솔 핸들을 물려주는 것과 같은 이유다.
    #
    # **이것이 사람을 흉내 내는 것임을 숨기지 않는다.** 아래 판정 줄이 그것을
    # 말하고, 프롬프트가 실제로 떴는지도 확인한다.
    printf 'yes\n' | script -qec \
        "$BIN run --plugin $PLUGIN --out-dir $WORK/run --state-dir $WORK/state" \
        /dev/null > "$OUT/run.log" 2>&1
    RC=$?
    if grep -q "승인할 사람이 없습니다" "$OUT/run.log"; then
        echo "    ** pty 를 만들지 못했다 — 코어가 터미널이 아니라고 판단했다"
    elif grep -q "진행하려면" "$OUT/run.log"; then
        APPROVED=1
        echo "    승인 프롬프트가 떴고 '예' 로 답했다"
    else
        echo "    ** 승인 프롬프트가 뜨지 않았다 — 대화형 경로를 재지 못했다"
    fi
else
    echo "[*] 치료: run --yes (무인)"
    "$BIN" run --plugin "$PLUGIN" --out-dir "$WORK/run" --yes --state-dir "$WORK/state" \
        > "$OUT/run.log" 2>&1
    RC=$?
fi
echo "    종료 코드 $RC"
# pty 를 거친 로그에는 `\r` 이 섞인다. 그대로 뿌리면 줄이 겹쳐 보인다.
tr -d '\r' < "$OUT/run.log" | grep -E '^\s*(수행|실패|보류) ' | sed 's/^/      /' || true

# **코어가 하지 않기로 한 것.** 계획서가 이유와 함께 적는다.
#
# 무인 모드(`--yes`)에서는 `cert_store.remove` 가 여기로 간다 — 신뢰 루트를
# 지우려면 인증서 주체를 읽고 판단할 사람이 필요하고, 그 사람이 없기 때문이다
# (`derive.rs::gate_needs_a_human`). 그것은 결함이 아니라 설계다. 그러나
# **기계가 깨끗해졌다는 뜻도 아니므로** 판정은 미결로 내린다.
: > "$WORK/deferred.txt"
[ -f "$WORK/run/plan.json" ] && sed -n 's/^ *"at": *"target: \(.*\)",*$/\1/p' "$WORK/run/plan.json" \
    > "$WORK/deferred.txt"

echo "[*] 3/3 치료 후 상태"
capture treated
echo "    항목 $(wc -l < "$OUT/state-treated.tsv")건"

# ─────────────────────────────────────────── 판정

val() { awk -F'\t' -v k="$2" '$1 == k { print $2; exit }' "$OUT/state-$1.tsv"; }

# `[Desktop Entry]` 의 `Exec=` 값. 다른 절(`[Desktop Action …]`)의 것은 그 동작의
# 것이지 항목의 것이 아니다 — 수집기와 같은 판단이다.
desktop_exec() {
    awk '/^\[/ { e = ($0 == "[Desktop Entry]") } e && /^Exec=/ { sub(/^Exec=/, ""); print; exit }' "$1"
}
# `Exec=` 줄만 뺀 나머지. 그 줄 말고는 아무것도 달라지면 안 된다.
without_exec() {
    awk '/^\[/ { e = ($0 == "[Desktop Entry]") } !(e && /^Exec=/)' "$1"
}
# 공백을 하나로 고른 토큰 열.
norm_tokens() { printf '%s' "$1" | awk '{ $1 = $1; print }'; }
# 첫 열에서 둘째 열의 토큰을 **앞에서부터 하나씩** 뺀 나머지.
minus_tokens() {
    awk -v all="$1" -v drop="$2" 'BEGIN {
        nd = split(drop, D, " "); na = split(all, A, " ")
        for (d = 1; d <= nd; d++)
            for (i = 1; i <= na; i++) if (A[i] == D[d]) { A[i] = ""; break }
        out = ""
        for (i = 1; i <= na; i++) if (A[i] != "") out = (out == "" ? A[i] : out " " A[i])
        print out
    }'
}

# 구조적 설정에서 **키 하나만 뺀 나머지**를 정규형(정렬된 JSON)으로 낸다.
#
# 그 키가 없으면 **종료 코드 1** — 없는 것을 뺐다고 말하지 않는다. 그때 그
# 자리는 '재지 못한 것' 이고, '달라지지 않았다' 를 통과로 읽으면 안 된다.
# Windows 하네스의 `Remove-JsonKeyPath` + `ConvertTo-CanonicalJson` 과 같은
# 규칙이다 — 두 하네스가 같은 것을 재야 한다.
json_minus_key() {
    python3 - "$1" "$2" <<'PY'
import io, json, sys
try:
    doc = json.load(io.open(sys.argv[1], encoding='utf-8'))
except Exception as e:
    sys.stderr.write('JSON 이 아니다: %s\n' % e)
    raise SystemExit(2)
segs = sys.argv[2].split('.')
node = doc
for s in segs[:-1]:
    if not isinstance(node, dict) or s not in node:
        raise SystemExit(1)
    node = node[s]
if not isinstance(node, dict) or segs[-1] not in node:
    raise SystemExit(1)
del node[segs[-1]]
sys.stdout.write(json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=1))
PY
}
# 같은 정규형으로 읽는다. 들여쓰기·키 순서 차이를 내용 차이로 세지 않는다.
json_canon() {
    python3 - "$1" <<'PY'
import io, json, sys
try:
    doc = json.load(io.open(sys.argv[1], encoding='utf-8'))
except Exception as e:
    sys.stderr.write('JSON 이 아니다: %s\n' % e)
    raise SystemExit(2)
sys.stdout.write(json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=1))
PY
}

MISMATCH=(); DEFERRED=(); UNJUDGED=(); UNMEASURED=(); MEASURED=0; MUST_MEASURED=0
# 내용 검사 — 밟는 자리 중 `line=` · `args=` · `key_path=` 로 판정하는 것들의
# 갈래 수다.
CONTENT_N=$(( $(ls -1 "$WORK/lines" 2>/dev/null | wc -l) + $(ls -1 "$WORK/args" 2>/dev/null | wc -l) + $(ls -1 "$WORK/keys" 2>/dev/null | wc -l) )); CONTENT_MEASURED=0

while IFS=$'\t' read -r op target kind n; do
    if grep -qxF "$target" "$WORK/deferred.txt" 2>/dev/null; then
        DEFERRED+=("$target  ($op)")
        continue
    fi
    c="$(val clean "$target")"; i="$(val infected "$target")"; t="$(val treated "$target")"

    if [ -f "$WORK/args/$n" ]; then
        # **그 인자만 빠지고 나머지는 그대로여야 한다.**
        #
        # 기대값을 우리가 만든다 — 감염 상태의 `Exec=` 토큰에서 사전 등록
        # 자료가 지목한 인자 토큰을 앞에서부터 하나씩 뺀다. 제품이 무슨 규칙으로
        # 가르는지는 보지 않는다(그것을 베끼면 검증자가 피검증자가 된다).
        [ -f "$WORK/snap/infected/$n" ] || { UNMEASURED+=("$target — 감염 상태에 파일이 없다"); continue; }
        want_args="$(cat "$WORK/args/$n")"
        inf_exec="$(desktop_exec "$WORK/snap/infected/$n")"
        [ -n "$inf_exec" ] || { UNMEASURED+=("$target — 감염 상태에 Exec= 가 없다"); continue; }
        CONTENT_MEASURED=$((CONTENT_MEASURED + 1)); MEASURED=$((MEASURED + 1))

        [ -f "$WORK/snap/treated/$n" ] || { MISMATCH+=("$target|파일이 남아 있어야 한다|사라졌다"); continue; }
        want="$(minus_tokens "$inf_exec" "$want_args")"
        got="$(norm_tokens "$(desktop_exec "$WORK/snap/treated/$n")")"
        [ "$want" = "$got" ] || MISMATCH+=("$target|Exec= 가 '$want' 여야 한다|'$got'")
        # 다른 줄은 손대지 않았어야 한다. `Exec=` 만 빼고 견준다.
        if ! cmp -s <(without_exec "$WORK/snap/infected/$n") <(without_exec "$WORK/snap/treated/$n"); then
            MISMATCH+=("$target|Exec= 말고 다른 줄은 그대로여야 한다|달라졌다")
        fi
        continue
    fi

    if [ -f "$WORK/keys/$n" ]; then
        # 키 검사. **감염 상태에 그 키가 있어야 잰 것이다.**
        #
        # 기대값을 우리가 만든다 — 감염본에서 지목한 키 하나만 뺀다. 제품이
        # 무슨 규칙으로 지우는지는 보지 않는다(그것을 베끼면 검증자가
        # 피검증자가 된다).
        [ -f "$WORK/snap/infected/$n" ] || { UNMEASURED+=("$target — 감염 상태에 파일이 없다"); continue; }
        kp="$(cat "$WORK/keys/$n")"
        if ! json_minus_key "$WORK/snap/infected/$n" "$kp" > "$WORK/want.$n" 2>/dev/null; then
            UNMEASURED+=("$target — 감염 상태에 '$kp' 가 없다 (픽스처가 넣지 않았다)")
            continue
        fi
        MEASURED=$((MEASURED + 1)); CONTENT_MEASURED=$((CONTENT_MEASURED + 1))

        [ -f "$WORK/snap/treated/$n" ] || { MISMATCH+=("$target|파일이 있어야 한다|사라졌다"); continue; }
        if ! json_canon "$WORK/snap/treated/$n" > "$WORK/got.$n" 2>/dev/null; then
            MISMATCH+=("$target|JSON 이어야 한다|읽히지 않는다")
            continue
        fi
        if ! cmp -s "$WORK/want.$n" "$WORK/got.$n"; then
            d="$(diff "$WORK/want.$n" "$WORK/got.$n" | head -6 | tr '\n' ' ')"
            MISMATCH+=("$target|'$kp' 만 빠져야 한다|$d")
        fi
        continue
    fi

    if [ -f "$WORK/lines/$n" ]; then
        # 줄 검사. **감염 상태에 그 줄이 있어야 잰 것이다.**
        [ -f "$WORK/snap/infected/$n" ] || { UNMEASURED+=("$target — 감염 상태에 파일이 없다"); continue; }
        missing=0
        while IFS= read -r want_line; do
            grep -qxF "$want_line" "$WORK/snap/infected/$n" || missing=1
        done < "$WORK/lines/$n"
        [ "$missing" -eq 1 ] && { UNMEASURED+=("$target — 감염 상태에 지울 줄이 없다"); continue; }
        MEASURED=$((MEASURED + 1)); CONTENT_MEASURED=$((CONTENT_MEASURED + 1))

        [ -f "$WORK/snap/treated/$n" ] || { MISMATCH+=("$target|파일이 있어야 한다|사라졌다"); continue; }
        # 기대: 감염 상태에서 **그 줄들만** 빠진 것.
        grep -vxF -f "$WORK/lines/$n" "$WORK/snap/infected/$n" > "$WORK/want.$n" || true
        if ! cmp -s "$WORK/want.$n" "$WORK/snap/treated/$n"; then
            d="$(diff "$WORK/want.$n" "$WORK/snap/treated/$n" | head -6 | tr '\n' ' ')"
            MISMATCH+=("$target|그 줄들만 빠져야 한다|$d")
        fi
        continue
    fi

    if [ "$kind" = gone ]; then
        [ "$c" != "$i" ] && MEASURED=$((MEASURED + 1))
        [ "$t" = absent ] || MISMATCH+=("$target|없어야 한다|$t")
    else
        # **판정 불가를 잰 것으로 세지 않는다.** 2026-09-06 감사 전에는
        # `MEASURED` 를 여기서 먼저 올리고 나서 `판정 불가` 로 분류했다. 그래서
        # `ldso-preload` 가 `잰 곳 4/4` 로 적히는데 그중 하나
        # (`org.example.Editor.desktop`)는 견줄 청정 값이 없어 아무것도 재지
        # 못한 자리였다. 숫자가 스스로 거짓말을 했다.
        if [ "$c" = absent ]; then
            UNJUDGED+=("$target")
        else
            [ "$c" != "$i" ] && MEASURED=$((MEASURED + 1))
            [ "$c" != "$t" ] && MISMATCH+=("$target|$c|$t")
        fi
    fi
done < "$WORK/scope.tsv"

# 남아야 하는 자리 — **감염 상태와 견준다.**
DAMAGED=()
while read -r m; do
    [ -n "$m" ] || continue
    i="$(val infected "$m")"; t="$(val treated "$m")"
    if [ "$i" = absent ]; then
        # 픽스처가 세우지 않았다. 그 상태의 '안 바뀜' 은 지키고 있다는 뜻이
        # 아니라 잴 것이 없었다는 뜻이다.
        UNMEASURED+=("$m — 감염 상태에 그 자리가 없다 (픽스처가 세우지 않았다)")
        continue
    fi
    MUST_MEASURED=$((MUST_MEASURED + 1))
    [ "$i" != "$t" ] && DAMAGED+=("$m|$i|$t")
done < "$WORK/must-remain.txt"

# **우리 자신이 남기는 흔적** (설계-03 §8 — 고정된 식별 가능한 이름). 재부팅 뒤
# 재검사를 걸면 코어가 이 둘을 심는다(P12). 판정에서 빼되 화면에는 띄운다 —
# 숨기면 다음 사람이 다시 조사한다(`Invoke-ExamApply.ps1` 의 `$ownTraces` 와 같은
# 규칙).
#
# **이름 일부가 아니라 경로 전체로 맞춘다.** 일부로 맞추면 `remedy-verify` 를
# 흉내 낸 검체 유닛도 빠진다. 바꿔 끼우다 남은 임시 파일(`.remedy-tmp`)은 넣지
# 않는다 — 그것이 남았으면 규칙 (2) 위반이고, 치료가 만든 변화로 잡혀야 맞다.
#
# systemd 가 init 이 아닌 컨테이너에서는 코어가 예약하지 않으므로 이 갈래는 늘
# 비고, 화면도 전과 같다.
OWN_TRACES=(
    /etc/systemd/system/remedy-verify.service
    /etc/systemd/system/multi-user.target.wants/remedy-verify.service
)
own_trace() {
    local o
    for o in "${OWN_TRACES[@]}"; do [ "$1" = "$o" ] && return 0; done
    return 1
}

# 범위 밖 — 여기서는 청정 기준이 맞다. 치료 전에는 청정과 같았는데 치료 뒤에
# 달라진 것이 부수 피해다.
CAUSED=(); OWN=(); NOISE=0
while IFS=$'\t' read -r key _v; do
    awk -F'\t' -v k="$key" '$2 == k { found = 1 } END { exit !found }' "$WORK/scope.tsv" && continue
    # 남아야 하는 자리는 위에서 이미 판정했다. 여기서 또 세면 한 건이 두 줄로
    # 적히고, 더 나쁘게는 청정에 없는 자리라 `NOISE` 로 조용히 묻힌다.
    grep -qxF "$key" "$WORK/must-remain.txt" && continue
    c="$(val clean "$key")"; i="$(val infected "$key")"; t="$(val treated "$key")"
    [ -z "$c" ] && c=absent; [ -z "$i" ] && i=absent; [ -z "$t" ] && t=absent
    [ "$c" = "$t" ] && continue
    if [ "$c" != "$i" ]; then NOISE=$((NOISE + 1))
    elif own_trace "$key"; then OWN+=("$key|$c|$t")
    else CAUSED+=("$key|$c|$t"); fi
done < <(cat "$OUT/state-clean.tsv" "$OUT/state-infected.tsv" "$OUT/state-treated.tsv" | cut -f1 | sort -u | sed 's/$/\t/')

# 줄 머리에 묶지 않는다 — 2026-09-06 부터 이 문구는 마무리 표의 값 자리
# (`결과 : … (4건 수행 완료)`)에 온다. 게이트가 그것을 "수행 0건" 으로 잡았다.
TRACE_ACTIONS="$(grep -o '[0-9][0-9]*건 수행 완료' "$OUT/run.log" | tail -1 | sed 's/건 수행 완료//')"
[ -n "$TRACE_ACTIONS" ] || TRACE_ACTIONS=0

echo
echo "===== 채점 5. 실기기 치료 ====="
echo "  위협      $THREAT"
echo "  플러그인  $PLUGIN"
echo "  종료 코드 $RC   (1=완전 치료 · 3=부분 실패 · 5=guard 정지)"
SCOPE_N=$(wc -l < "$WORK/scope.tsv")
MUST_N=$(wc -l < "$WORK/must-remain.txt")
echo "  밟는 자리 ${SCOPE_N}곳 중 잰 변화 ${MEASURED}곳 · 남아야 하는 자리 ${MUST_N}곳 중 잰 것 ${MUST_MEASURED}곳 · 내용 검사 ${CONTENT_N}곳 중 잰 것 ${CONTENT_MEASURED}곳"
if [ "$ATTENDED" -eq 1 ]; then
    # **숨기지 않는다.** 이 회차의 합격은 "사람이 승인하면 깨끗해진다" 는 뜻이지
    # "사람 없이 깨끗해진다" 가 아니다.
    case "$REFUSAL_OK" in
        yes)     echo "  거부 확인  '아니오' 로 답하니 아무것도 하지 않았다" ;;
        no)      echo "  거부 확인  **승인하지 않았는데 기계가 바뀌었다**" ;;
        unknown) echo "  거부 확인  기계는 그대로인데 거부를 말하지 않았다" ;;
    esac
    if [ "$APPROVED" -eq 1 ]; then
        echo "  승인      대화형 — **하네스가 사람 대신 '예' 로 답했다**"
    else
        echo "  승인      **대화형 경로를 재지 못했다** (아래 미결)"
    fi
fi

show() { # 제목 · 색 없이 · 항목들
    local title="$1"; shift
    [ "$#" -eq 0 ] && return
    echo; echo "  $title"
    for e in "$@"; do
        printf '    %s\n' "${e%%|*}"
        case "$e" in *'|'*) printf '        기대: %s\n        실제: %s\n' \
            "$(printf '%s' "$e" | cut -d'|' -f2)" "$(printf '%s' "$e" | cut -d'|' -f3)" ;; esac
    done
}
show "범위 안 불일치 ${#MISMATCH[@]}건 — 사전 등록 자료가 지목한 성질이 이루어지지 않았다" "${MISMATCH[@]+"${MISMATCH[@]}"}"
show "치료가 만든 변화 ${#CAUSED[@]}건 — 범위 밖인데 치료 전에는 청정과 같았다" "${CAUSED[@]+"${CAUSED[@]}"}"
show "우리 흔적 ${#OWN[@]}건 — 재부팅 뒤 재검사 예약이다. 판정에서 뺐다 (설계-03 §8)" "${OWN[@]+"${OWN[@]}"}"
show "남아야 하는데 바뀌었다 ${#DAMAGED[@]}건 — must-remain.txt 가 지목한 자리다" "${DAMAGED[@]+"${DAMAGED[@]}"}"

if [ "${#DEFERRED[@]}" -gt 0 ]; then
    echo
    echo "  코어가 미룬 것 ${#DEFERRED[@]}건 — 계획하지 않기로 한 자리다 (plan.json 의 이유)"
    printf '    %s\n' "${DEFERRED[@]}"
    echo "    무인 모드에서 이것이 남는 것은 설계다. 그러나 기계가 깨끗해졌다는 뜻은 아니다."
    echo "    사람이 있는 회차로 재려면 --attended 를 준다."
fi
if [ "${#UNJUDGED[@]}" -gt 0 ]; then
    echo
    echo "  판정 불가 ${#UNJUDGED[@]}건 — 남아야 하는 자리인데 청정 기계에는 없었다"
    echo "    (픽스처가 위협과 함께 세운 것. 견줄 청정 값이 없다.)"
    printf '    %s\n' "${UNJUDGED[@]}"
fi
if [ "${#UNMEASURED[@]}" -gt 0 ]; then
    echo
    echo "  못 잰 곳 ${#UNMEASURED[@]}건 — 감염이 그 자리에 자국을 남기지 않았다"
    printf '    %s\n' "${UNMEASURED[@]}"
fi
UNKNOWN_N=$(wc -l < "$WORK/unknown-match.txt")
if [ "$UNKNOWN_N" -gt 0 ]; then
    echo
    echo "  볼 줄 모르는 매치 ${UNKNOWN_N}건 — 이 하네스에 그 검사가 없다"
    cat "$WORK/unknown-match.txt" | sed 's/^/    /'
fi
[ "$NOISE" -gt 0 ] && { echo; echo "  치료 전부터 있던 변화 ${NOISE}건 — 기계가 스스로 한 것이라 판정에서 뺐다"; }

# ─────────────────────────────────────────── 증거
#
# 저장소는 읽기 전용으로 마운트돼 있다. 여기서는 `/out` 에 쓰고, 위협 폴더로
# 옮기는 것은 호스트 쪽 `invoke-exam-apply.sh --record` 가 한다.
#
# **합격만 증거가 된다.** 미결과 불합격을 남기면 게이트가 그것을 보고 빨개지는데,
# 그때 사람이 할 일은 파일을 고치는 것이 아니라 다시 재는 것이다.
if [ "${#MISMATCH[@]}" -eq 0 ] && [ "${#CAUSED[@]}" -eq 0 ] && [ "${#DAMAGED[@]}" -eq 0 ] && [ "$UNKNOWN_N" -eq 0 ] && [ "$MEASURED" -gt 0 ]    && [ "${#DEFERRED[@]}" -eq 0 ] && [ "${#UNMEASURED[@]}" -eq 0 ]    && [ "$REFUSAL_OK" != no ] && [ "$REFUSAL_OK" != unknown ]    && { [ "$ATTENDED" -eq 0 ] || [ "$APPROVED" -eq 1 ]; }; then
    MODE=unattended; [ "$ATTENDED" -eq 1 ] && MODE=attended
    # 정답 폴더의 **파일 지도**. 폴더를 한 값으로 접으려면 "무엇을 어떤 순서로
    # 이어 붙이는가" 라는 규격이 생기고, 그것을 Rust · PowerShell · bash 세 곳에
    # 적으면 갈라진다. 지도끼리 견주면 각 언어가 아는 것은 파일 하나의 sha256
    # 뿐이다. 경로 구분자는 `/` 이고 정렬해 적는다.
    PLUGIN_DIR="$(dirname "$PLUGIN")"
    FILES="$(cd "$PLUGIN_DIR" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do
        printf '    "%s": "%s",\n' "$f" "$(sha256sum "$f" | cut -d' ' -f1)"
    done | sed '$ s/,$//')"
    cat > "$OUT/apply-result.json" <<JSON
{
  "schema": "remedy-exam-apply/4",
  "threat": "$THREAT",
  "platform": "linux",
  "mode": "$MODE",
  "verdict": "pass",
  "exit_code": $RC,
  "measured": $MEASURED,
  "scope_targets": $(wc -l < "$WORK/scope.tsv"),
  "trace": {
    "host": "$TRACE_HOST",
    "stages": [
$(awk -F'\t' '{ printf "%s      { \"stage\": \"%s\", \"at\": \"%s\", \"sha256\": \"%s\", \"counts\": { \"rows\": %s } }", (NR > 1 ? ",\n" : ""), $1, $2, $3, $4 } END { print "" }' "$WORK/trace.tsv")
    ],
    "actions_done": $TRACE_ACTIONS
  },
  "content_checks": $CONTENT_N,
  "content_measured": $CONTENT_MEASURED,
  "must_remain": $MUST_N,
  "must_remain_measured": $MUST_MEASURED,
  "plugin_files": {
$FILES
  },
  "expected_ops_sha256": "$(sha256sum "$EXPECTED" | cut -d' ' -f1)",
  "must_remain_sha256": "$(sha256sum "$MUST_FILE" | cut -d' ' -f1)",
  "binary_sha256": "$(sha256sum "$BIN" | cut -d' ' -f1)",
  "ran_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
    echo
    echo "  증거를 만들었다 — 위협 폴더에 두려면 호스트에서 --record 를 준다"
fi

echo
if [ "$REFUSAL_OK" = no ]; then
    # 승인하지 않았는데 기계가 바뀌었다. 이 도구가 낼 수 있는 최악의 실패이고
    # 다른 어떤 판정보다 먼저 말해야 한다.
    echo "  실패 채점 5 불합격 — **승인 거부가 지켜지지 않았다**"
    exit 1
elif [ "$REFUSAL_OK" = unknown ]; then
    echo "  미결 — 거부했을 때 기계는 그대로였지만 도구가 그것을 말하지 않았다."
    exit 2
elif [ "$ATTENDED" -eq 1 ] && [ "$APPROVED" -eq 0 ]; then
    # 대화형으로 재겠다고 해 놓고 그 경로를 못 밟았다. 그 상태의 결과는
    # 무인 회차와 같은 것도 아니고 대화형 회차도 아니다 — 아무것도 아니다.
    echo "  미결 — 대화형 승인 경로를 재지 못했다. $OUT/run.log 를 볼 것."
    exit 2
elif [ "$MEASURED" -eq 0 ]; then
    echo "  미결 — 감염이 관측 범위 안에 아무 자국도 남기지 않았다."
    echo "         잴 것이 없었으므로 '불일치 0' 을 통과로 읽으면 안 된다."
    exit 2
elif [ "${#MISMATCH[@]}" -gt 0 ] || [ "${#CAUSED[@]}" -gt 0 ] || [ "${#DAMAGED[@]}" -gt 0 ]; then
    echo "  실패 채점 5 불합격 — 범위 안 불일치 ${#MISMATCH[@]}건 · 치료가 만든 변화 ${#CAUSED[@]}건 · 남아야 하는데 바뀌었다 ${#DAMAGED[@]}건"
    exit 1
elif [ "${#DEFERRED[@]}" -gt 0 ] || [ "${#UNMEASURED[@]}" -gt 0 ] || [ "$UNKNOWN_N" -gt 0 ]; then
    echo "  미결 — 잰 자리는 전부 맞았지만 못 잰 자리가 있다. 통과로 읽으면 안 된다."
    exit 2
else
    echo "  OK   채점 5 합격 — 위협이 밟은 자리가 전부 사전 등록 자료대로 됐다"
    exit 0
fi
