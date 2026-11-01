#!/bin/bash
# CI 의 Linux 잡을 **로컬 리눅스**에서 대신 돌린다.
#
# # 왜 필요한가
#
# P2 에서 remedy-core 가 non-Windows 에서 컴파일되지 않는 상태로 커밋됐고,
# **아무도 몰랐다.** CI 가 한 번도 실행되지 않았기 때문이다(러너 부재). Windows
# 에서만 개발하면 이 계열의 결함은 원리적으로 보이지 않는다.
#
# CI 가 돌기 시작하면 이 스크립트는 보조 수단이 된다. 그전까지는 유일한 수단이다.
#
# # 전제
#
# 사내망이 TLS 를 가로채는 환경에서는 리눅스 쪽 rustup·cargo 가 crates.io 에
# 닿지 못한다. 그래서 **Windows 가 이미 받아 둔 레지스트리 캐시를 빌려** 오프라인
# 으로 돈다. 먼저 Windows 에서 한 번 채워 둘 것:
#
#     cargo fetch --target x86_64-unknown-linux-gnu
#
# # 쓰는 법 (WSL 또는 리눅스 셸)
#
#     REPO=<저장소의 WSL 경로> \
#     CARGO_HOME=<Windows 쪽 .cargo 의 WSL 경로> \
#     ci/linux-check-local.sh
#
# rustfmt·clippy·cargo-deny 는 컴포넌트 설치에 네트워크가 필요해 건너뛸 수 있다.
# **건너뛴 것은 통과가 아니다** — 마지막에 무엇을 못 봤는지 밝힌다.

set -u

REPO="${REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
# 호스트 빌드와 target/ 을 공유하면 지문이 서로를 무효화해 매번 전체 재빌드가 된다.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/remedy-linux-check}"
# rust-toolchain.toml 이 고정한 판을 **못 받을 때만** stable 로 내려간다.
# 판이 다르면 결과도 근사다 — 마지막에 어느 판으로 돌았는지 적는다.
#
# 한동안 여기서 무조건 `stable` 을 박았다. 그런데 고정 판에는
# `components = ["rustfmt", "clippy"]` 가 붙어 있고 stable 에는 없다 — 그래서
# **고정 판이 멀쩡히 설치돼 있는데도 fmt 와 clippy 가 매번 "도구 미설치" 로
# 건너뛰어졌다**(2026-09-19 실측: 그렇게 fmt 위반 146곳이 쌓였다).
export PATH="$HOME/.cargo/bin:$PATH"
PINNED=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$REPO/rust-toolchain.toml" 2>/dev/null)
if [ -n "${RUSTUP_TOOLCHAIN:-}" ]; then
    : # 부르는 쪽이 정했다. 그대로 따른다.
elif [ -n "$PINNED" ] && rustup toolchain list 2>/dev/null | grep -q "^${PINNED}-"; then
    : # 고정 판이 있다. rustup 이 rust-toolchain.toml 을 보고 알아서 고른다.
else
    export RUSTUP_TOOLCHAIN=stable
fi

cd "$REPO" || { echo "저장소를 찾을 수 없다: $REPO"; exit 1; }

OFFLINE=""
if [ -n "${CARGO_HOME:-}" ] && [ -d "${CARGO_HOME}/registry" ]; then
    OFFLINE="--offline"
fi

fail=0
skipped=()

run() {
    name="$1"; shift
    printf '%-10s ' "$name"
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "건너뜀 ($1 없음)"
        skipped+=("$name")
        return
    fi
    log="/tmp/remedy-linux-$name.log"
    if "$@" >"$log" 2>&1; then
        echo "통과"
    else
        code=$?
        # 도구가 없어서 못 돈 것은 실패가 아니다. 둘을 섞으면 "빨간 것을 무시하는
        # 습관" 이 생기고, 진짜 실패도 함께 무시된다.
        #
        # `command -v cargo` 로는 못 거른다 — cargo 는 있고 하위 명령이 없는
        # 경우(cargo-deny)가 여기 걸린다.
        if grep -qE "is not installed for the toolchain|no such command" "$log"; then
            echo "건너뜀 (도구 미설치)"
            skipped+=("$name")
        else
            echo "실패 (exit $code)"
            sed 's/^/    /' "$log" | tail -30
            fail=1
        fi
    fi
}

echo "저장소   : $REPO"
echo "툴체인   : $(rustc --version 2>/dev/null || echo '없음')"
echo "타깃 디렉터리: $CARGO_TARGET_DIR"
echo "오프라인 : ${OFFLINE:-아니오}"
echo

run fmt    cargo fmt --all -- --check
run clippy cargo clippy --workspace --all-targets $OFFLINE --quiet -- -D warnings
run arch   cargo xtask arch
run trace  cargo xtask trace
run schema cargo xtask schema
run corpus cargo test -p remedy-core --test corpus $OFFLINE --quiet
run test   cargo test --workspace --all-targets $OFFLINE --quiet
run deny   cargo deny check

echo
if [ ${#skipped[@]} -gt 0 ]; then
    echo "돌리지 못한 검사: ${skipped[*]}"
    echo "  이것은 통과가 아니다. CI 러너가 붙으면 그쪽에서 확인할 것."
fi

if [ $fail -eq 0 ]; then
    echo "돌린 검사는 전부 통과."
    # 건너뛴 것이 있으면 종료 코드로도 구분한다 — 스크립트를 CI 처럼 쓰는
    # 사람이 "0 이면 다 봤다" 로 읽으면 안 된다.
    [ ${#skipped[@]} -gt 0 ] && exit 2
    exit 0
fi
echo "실패한 검사가 있다."
exit 1
