#!/usr/bin/env bash
#
# `linux-static.sh` 를 **musl 크로스 컴파일러가 있는 컨테이너**에서 돌린다.
#
# # 왜 필요한가
#
# P0 의 판정은 **A(musl 기본 정적)** 이고 `rust-toolchain.toml` 이 그 타깃을
# 고정한다. 그런데 musl 빌드에는 `x86_64-linux-musl-gcc` 가 필요하다 —
# wasmtime 의 빌드 스크립트가 C 파일을 컴파일하기 때문이다(설계-09 P0).
#
# 개발 기계(WSL 등)에 그것이 없으면 `linux-static.sh` 는 A 를 건너뛰고
# **B(glibc +crt-static)를 채택했다고 보고한다.** 그 리포트만 보면 "musl 은
# 안 되는 방식" 으로 읽히는데, 사실은 **이 기계에 컴파일러가 없었을 뿐**이다.
# 판정을 뒤집는 것과 잴 수 없는 것은 다르고, 그 차이를 남기지 않으면 다음
# 사람이 근거를 다시 만들 수 없다.
#
# CI 러너 이미지에는 musl-tools 가 있으므로 이 스크립트는 **로컬 재현용**이다.
#
# # 쓰는 법 (저장소 루트에서)
#
#     docker run --rm -v "$PWD:/w" -w /w rust:1.96-bookworm bash ci/linux-static-docker.sh
#
#   PowerShell:
#     docker run --rm -v "${PWD}:/w" -w /w rust:1.96-bookworm bash ci/linux-static-docker.sh
#
#   crates 를 매번 받지 않으려면 명명 볼륨을 붙인다 (호스트의 ~/.cargo 는
#   건드리지 않는다):
#     -v remedy-cargo:/usr/local/cargo
set -uo pipefail

echo "== 준비 =="
rustc --version
apt-get update -qq
apt-get install -y -qq musl-tools >/dev/null

# cc-rs 는 **타깃 접두가 붙은 이름**을 먼저 찾는다. Debian 의 musl-tools 는 두
# 이름을 모두 두지만 배포판마다 다르므로, 없으면 링크를 건다. 이것이 없어서
# 실패하면 오류는 `failed to find tool "x86_64-linux-musl-gcc"` 로 나온다.
if ! command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
    ln -sf "$(command -v musl-gcc)" /usr/local/bin/x86_64-linux-musl-gcc
    echo "링크 생성: x86_64-linux-musl-gcc -> $(command -v musl-gcc)"
fi
echo "x86_64-linux-musl-gcc: $(command -v x86_64-linux-musl-gcc || echo '없음')"

rustup target add x86_64-unknown-linux-musl
rustup target add x86_64-unknown-linux-gnu

# **빌드는 컨테이너 안에서 한다.** 마운트된 호스트 볼륨 위에서 빌드하면
# 파일시스템 왕복 때문에 몇 배로 느리다. `git clone` 으로 가져오므로 `target/`
# 같은 무시 대상이 따라오지 않는다 — 산출물만 마운트로 되돌린다.
echo
echo "== 저장소 복제 =="
rm -rf /build
git config --global --add safe.directory /w
git clone -q /w /build || { echo "복제 실패: /w 가 저장소인지 확인할 것" >&2; exit 1; }
cd /build || exit 9
git log --oneline -1

echo
echo "== ci/linux-static.sh =="
bash ci/linux-static.sh
rc=$?

echo
echo "== 산출물 회수 =="
for f in linux-static-report.txt build-x86_64-unknown-linux-musl.log build-x86_64-unknown-linux-gnu.log; do
    [ -f "$f" ] || continue
    cp -f "$f" /w/ && echo "  회수: $f"
done

echo "SCRIPT_RC=$rc"
exit "$rc"
