#!/bin/bash
# CI 의 Linux 실기기 검증 잡 (설계-09 P12 후속).
#
# # 이 잡의 기계는 **잡의 컨테이너 자신**이다
#
# 하네스는 `/etc/hosts` 를 고치고 systemd 유닛을 지우고 프로세스를 죽인다.
# 개발 기계에서 돌릴 수 없어 `invoke-linux-verify.sh` 는 컨테이너를 띄우는데,
# **CI 잡은 이미 컨테이너 안에서 돈다.** 거기서 또 docker 를 부르려면
# docker-in-docker 가 필요하고, 그러면 `-v $PWD:/repo` 가 잡의 파일이 아니라
# dind 호스트의 파일을 가리켜 조용히 엉뚱한 것을 마운트한다.
#
# 그래서 여기서는 컨테이너를 띄우지 않고 **지금 이 컨테이너를 실험대로 쓴다.**
#
# > **셸 러너에 떨어지면 이 잡은 반드시 실패해야 한다.** 러너 호스트의
# > `/etc/hosts` 를 고치고 프로세스를 죽이게 되기 때문이다.
# > `new-fixtures.sh` 의 컨테이너 검사가 그것을 막고, 이 스크립트는 그 거절을
# > 통과로 바꾸지 않는다.
#
# # 두 가지를 잰다
#
#   1. **검증 하네스** — 수집·판정·계획·치료·격리·복원·저널이 진짜 `/etc`
#      위에서 도는가 (`verify-linux.sh`, 20 항목).
#
#   2. **위협 스냅샷이 낡지 않았는가** — 커밋된 감염 스냅샷을 다시 떠서
#      비교한다. 수집기를 고치면 그 자료가 낡는데, 2026-09-04 까지 **그것을
#      알려 주는 것이 아무것도 없었다.**
#
#      `ctime` 은 뺀다 — 아이노드가 바뀐 시각이라 뜰 때마다 다르고, 그것은
#      기계의 사실이지 자료의 낡음이 아니다.
#
# # 이미지
#
# `cert_store.remove` 가 `update-ca-certificates` 를 요구한다. 없는 이미지에서
# 그 Op 은 거부되고(그것이 옳은 동작이다) 하네스가 그 자리를 **"못 잼"** 으로
# 적는다 — 실패가 아니지만 통과도 아니다. `rust:1.96-bookworm` 에는 있다.
#
# # 쓰는 법
#
#     ci/linux-testbed.sh                 # 둘 다
#     ci/linux-testbed.sh --verify-only
#     ci/linux-testbed.sh --snapshots-only

set -u
# 이 스크립트는 한국어 문구를 읽는다. 기본 언어는 영어다 (2026-09-06).
export REMEDY_LANG=ko

REPO="${REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
BIN="${BIN:-}"
OUT="${OUT:-$REPO/testbed-out}"
DO_VERIFY=1
DO_SNAPSHOTS=1

while [ $# -gt 0 ]; do
    case "$1" in
        --bin)            BIN="${2:-}"; shift 2 ;;
        --out)            OUT="${2:-}"; shift 2 ;;
        --verify-only)    DO_SNAPSHOTS=0; shift ;;
        --snapshots-only) DO_VERIFY=0; shift ;;
        *) echo "모르는 인자: $1"; exit 2 ;;
    esac
done

cd "$REPO" || { echo "저장소를 찾을 수 없다: $REPO"; exit 1; }
mkdir -p "$OUT"

# ── 바이너리 ────────────────────────────────────────────────────────
#
# **배포 프로필로 만든다.** 하네스가 재는 것 중 하나가 *"서명이 없다는 이유로
# 기능을 막지 않는다"* 이고, 그것은 릴리스 빌드에서만 뜻이 있다.
if [ -z "$BIN" ]; then
    BIN="${CARGO_TARGET_DIR:-$REPO/target}/release/remedy"
    if [ ! -x "$BIN" ]; then
        echo "[*] 빌드: cargo build --release -p remedy-cli"
        cargo build --release -p remedy-cli || exit 1
    fi
fi
[ -x "$BIN" ] || { echo "바이너리가 없다: $BIN"; exit 1; }
echo "바이너리 $BIN"
echo "이미지   $( . /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-불명}" )"

fail=0

# ── 1. 검증 하네스 ──────────────────────────────────────────────────
if [ "$DO_VERIFY" -eq 1 ]; then
    bash testbed/harness/linux/verify-linux.sh --bin "$BIN" --out "$OUT/verify" || fail=1
fi

# ── 2. 위협 스냅샷 낡음 ─────────────────────────────────────────────
#
# 다시 떠서 커밋된 것과 비교한다. 다르면 **자료가 낡은 것이다** — 수집기가
# 바뀌었거나 이미지가 바뀌었거나 둘 다다. 어느 쪽이든 사람이 봐야 한다.
if [ "$DO_SNAPSHOTS" -eq 1 ]; then
    echo
    echo "── 위협 스냅샷이 지금 수집기와 맞는가 ──"
    for t in ldso-preload tls-intercept; do
        f="testbed/ai-exam/threats/$t/infected/$t.json"
        cp "$f" "$OUT/$t.committed.json"
        if ! bash testbed/harness/linux/new-threat-snapshot.sh \
                --threat "$t" --bin "$BIN" --local > "$OUT/$t.capture.log" 2>&1; then
            echo "  실패 $t — 다시 뜨지 못했다"
            sed 's/^/       /' "$OUT/$t.capture.log" | tail -5
            fail=1
            cp "$OUT/$t.committed.json" "$f"
            continue
        fi
        # `ctime` 만 빼고 비교한다. 그것은 뜰 때마다 다르고 자료의 낡음이 아니다.
        grep -v '"ctime"' "$OUT/$t.committed.json" > "$OUT/$t.a" 2>/dev/null
        grep -v '"ctime"' "$f"                     > "$OUT/$t.b" 2>/dev/null
        if diff -q "$OUT/$t.a" "$OUT/$t.b" > /dev/null 2>&1; then
            echo "  OK   $t — 다시 떠도 같다"
        else
            echo "  실패 $t — 다시 뜬 것이 커밋된 것과 다르다 (ctime 제외)"
            diff -u "$OUT/$t.a" "$OUT/$t.b" | head -30 | sed 's/^/       /'
            echo "       자료가 낡았다. 다시 떠서 커밋할 것:"
            echo "         testbed/harness/linux/new-threat-snapshot.sh --threat $t"
            fail=1
        fi
        # **작업 트리를 되돌린다.** CI 잡이 스냅샷을 고쳐 놓고 끝나면 다음
        # 단계가 무엇을 보고 있는지 알 수 없게 된다.
        cp "$OUT/$t.committed.json" "$f"
        rm -f "$OUT/$t.a" "$OUT/$t.b"
    done
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "Linux 실기기 검증 통과."
else
    echo "실패가 있다. $OUT 를 볼 것."
fi
exit "$fail"
