#!/usr/bin/env bash
#
# P0 실증 — Linux 정적화 방식을 결정한다 (설계-09 P0).
#
# 왜 스크립트인가: yara-x 는 wasmtime 을 의존하고 wasmtime 의 빌드 스크립트는
# C 파일 하나를 컴파일한다. 그래서 "빈 크레이트가 링크되는가" 로는 답이 나오지
# 않고, 실제로 yara-x 를 포함한 바이너리를 만들어 봐야 한다.
#
# 두 후보를 모두 시도하고 결과를 보고한다. 추정하지 않는다.
#   A) x86_64-unknown-linux-musl        — Rust 기본으로 정적
#   B) x86_64-unknown-linux-gnu + crt-static — yara-x 상위가 릴리스에 쓰는 방식
set -uo pipefail

REPORT="linux-static-report.txt"
LOGS=(build-x86_64-unknown-linux-musl.log build-x86_64-unknown-linux-gnu.log)

# **이전 산출물을 먼저 치운다.**
#
# 이 스크립트는 리포트를 남기는 것이 목적이라 워킹트리에 쓴다. 그런데 도커
# 러너에서 root 로 한 번 돌면 이 파일들이 **root 소유 644** 로 남고, 그다음
# 일반 사용자로 돌릴 때 `tee` 와 리다이렉션이 **조용히** 실패한다. `set -e` 가
# 없으므로 스크립트는 그대로 진행하고, 빌드가 돌지 않은 채 `tail` 이 **이전
# 실행의 로그**를 읽어 그것을 이번 결과로 보고한다.
#
# 실측으로 겪었다: 화면에는 "빌드 6분 48초 후 실패" 로 보였으나 `time` 은
# 0.16 초였고, 로그에 찍힌 경로(`/w/crates/...`)는 두 달 전 도커 실행의 것이었다.
# **거짓 진단이 나오는 실패는 실패보다 나쁘다.**
#
# 디렉터리 쓰기 권한만 있으면 남의 소유 파일도 지워지므로 대개 이것으로 풀린다.
# 지울 수 없으면 그 자리에서 멈춘다 — 못 쓰는 채로 도는 것보다 낫다.
rm -f "$REPORT" "${LOGS[@]}" 2>/dev/null
for f in "$REPORT" "${LOGS[@]}"; do
    [ -e "$f" ] || continue
    {
        echo "이전 산출물을 지울 수 없다: $f"
        ls -l "$f" 2>/dev/null
        echo "다른 사용자(도커 러너의 root 등)가 만든 파일이다."
        echo "지운 뒤 다시 돌릴 것:  sudo rm -f $f"
    } >&2
    exit 1
done
# 디렉터리 자체가 읽기 전용일 수도 있다. 여기서 확인하지 않으면 첫 `log` 가
# 조용히 실패하고 위와 같은 자리로 되돌아간다.
if ! : > "$REPORT" 2>/dev/null; then
    echo "리포트를 만들 수 없다: $REPORT — 작업 디렉터리 쓰기 권한을 확인할 것." >&2
    exit 1
fi

log() { echo "$*" | tee -a "$REPORT"; }

log "== P0 Linux 정적화 실증 =="
log "rustc: $(rustc --version)"
log "date : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""

# 정적 링크 여부를 판정한다. 동적 로더가 없으면 정적이다.
is_static() {
    local bin="$1"
    if command -v file >/dev/null 2>&1; then
        file "$bin" | grep -qE "statically linked|static-pie" && return 0
    fi
    if command -v ldd >/dev/null 2>&1; then
        ldd "$bin" 2>&1 | grep -q "not a dynamic executable" && return 0
    fi
    return 1
}

try_target() {
    local target="$1" flags="$2" label="$3"
    log "--- 후보: $label ($target) ---"

    if ! rustup target add "$target" >/dev/null 2>&1; then
        log "  타깃 추가 실패 — 건너뜀"
        return 1
    fi

    if ! RUSTFLAGS="$flags" cargo build --release --target "$target" -p remedy-cli \
         >"build-$target.log" 2>&1; then
        log "  빌드 실패. 마지막 20줄:"
        tail -20 "build-$target.log" | sed 's/^/    /' | tee -a "$REPORT"
        return 1
    fi

    local bin="target/$target/release/remedy"
    log "  빌드 성공: $(stat -c%s "$bin" 2>/dev/null || echo '?') bytes"

    if is_static "$bin"; then
        log "  정적 링크: 예"
    else
        log "  정적 링크: *** 아니오 *** (동적 의존 존재)"
        command -v ldd >/dev/null 2>&1 && ldd "$bin" 2>&1 | sed 's/^/    /' | tee -a "$REPORT"
        return 1
    fi

    # 링크만 되고 동작하지 않으면 의미가 없다. yara-x 스파이크까지 확인한다.
    if "./$bin" selftest >>"$REPORT" 2>&1; then
        log "  selftest: 통과 (yara-x 스파이크 포함)"
        return 0
    fi
    log "  selftest: *** 실패 ***"
    return 1
}

MUSL_OK=1
GNU_OK=1
try_target "x86_64-unknown-linux-musl" "" "A. musl 기본 정적" || MUSL_OK=0
log ""
try_target "x86_64-unknown-linux-gnu" "-C target-feature=+crt-static" \
    "B. glibc +crt-static" || GNU_OK=0
log ""

log "== 판정 =="
if [ "$MUSL_OK" = 1 ]; then
    log "채택: A (musl 기본 정적)"
    log "근거: 추가 플래그 없이 정적이며 selftest 통과"
    exit 0
elif [ "$GNU_OK" = 1 ]; then
    log "채택: B (glibc +crt-static)"
    log "근거: musl 실패, glibc 정적 링크가 selftest 통과"
    exit 0
else
    log "*** 두 후보 모두 실패 — P0 를 완료로 볼 수 없다 ***"
    log "확인할 것: musl 크로스 C 컴파일러 존재 여부(wasmtime 의 cc 의존),"
    log "           러너 이미지의 build-essential / musl-tools 설치 여부"
    exit 1
fi
