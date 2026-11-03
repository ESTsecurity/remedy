#!/usr/bin/env bash
#
# 배포 잡(`.github/workflows/release.yml`)의 두 OS 가 함께 쓰는 단계 — 키 · 서명 · 검증.
#
#   ci/release.sh pubkey                         공개키를 준비하고 REMEDY_TRUST_ANCHOR 를 잡의 환경에
#   ci/release.sh sign <플러그인 폴더>             그 키로 서명한다(서명 시각은 이 커밋의 시각)
#   ci/release.sh verify <remedy> <플러그인 폴더>  박힌 앵커로 확인하고, 거부할 것을 거부하는가
#   ci/release.sh readme <README.txt>            꾸러미의 안내문이 앵커 판인가
#
# # 키는 어디서 오는가
#
# 태그(`v*`) 실행은 Environment `release` 의 비밀로 서명하고 저장소 변수의 공개키를
# 박는다. PR 의 시험 실행은 그 자리에서 만든 **일회용 키**로 같은 차례를 돈다 — 비밀을
# 쓰지 않고, 아무것도 올리지 않는다.
#
# 비밀은 `sign` 한 단계에만 들어오고 개인키 파일은 그 단계가 끝나면 지운다. 키 파일은
# 저장소 밖(`$RUNNER_TEMP`)에 둔다 — 작업 트리에 두면 꾸러미나 올리는 파일에 섞일 수 있다.
set -euo pipefail

base=${RUNNER_TEMP:?RUNNER_TEMP 가 없다 — 잡 안에서 부를 것}
command -v cygpath >/dev/null 2>&1 && base=$(cygpath -u "$base")
KEYS="$base/remedy-keys"
SIGN_KEY="$KEYS/sign.key"
SIGN_PUB="$KEYS/sign.pub"

tagged() { [ "${GITHUB_EVENT_NAME:-}" = push ]; }

# 일회용 키쌍 <이름>.pub · <이름>.key · <이름>.pass — 시험 실행의 키와 반대 확인의 '다른 키'.
throwaway() {
    local pass
    # keygen 은 있는 키를 덮어쓰지 않는다 — 일회용이라 앞 것을 먼저 치운다.
    rm -f "$KEYS/$1.pub" "$KEYS/$1.key" "$KEYS/$1.pass"
    pass=$(openssl rand -hex 16)
    printf '%s' "$pass" >"$KEYS/$1.pass"
    REMEDY_SIGN_PASSWORD=$pass cargo xtask sign keygen \
        --public-key "$KEYS/$1.pub" --secret-key "$KEYS/$1.key" >/dev/null
}

pubkey() {
    mkdir -p "$KEYS"
    if tagged; then
        if [ -z "${ANCHOR:-}" ]; then
            echo "::error::저장소 변수 REMEDY_TRUST_ANCHOR 가 비었다"
            exit 1
        fi
        printf 'untrusted comment: minisign public key\n%s\n' "$ANCHOR" >"$SIGN_PUB"
    else
        throwaway sign
    fi
    local anchor
    anchor=$(sed -n 2p "$SIGN_PUB" | tr -d '\r')
    {
        echo "REMEDY_TRUST_ANCHOR=$anchor"
        echo "RELEASE_PUBKEY=$SIGN_PUB"
    } >>"${GITHUB_ENV:?}"
    echo "앵커(공개키): $anchor"
}

sign() {
    local dir=${1:?플러그인 폴더}
    local at
    at=$(date -u -d "@$(git log -1 --format=%ct)" +%Y-%m-%dT%H:%M:%SZ)
    if tagged; then
        if [ -z "${SECRET_KEY:-}" ] || [ -z "${SECRET_PASSWORD:-}" ]; then
            echo "::error::서명 비밀이 없다 — Environment release 에서 도는 잡인가"
            exit 1
        fi
        trap 'rm -f "$SIGN_KEY"' EXIT
        printf '%s\n' "$SECRET_KEY" >"$SIGN_KEY"
        REMEDY_SIGN_PASSWORD=$SECRET_PASSWORD cargo xtask sign plugin \
            --dir "$dir" --secret-key "$SIGN_KEY" --signed-at "$at"
    else
        REMEDY_SIGN_PASSWORD=$(cat "$KEYS/sign.pass") cargo xtask sign plugin \
            --dir "$dir" --secret-key "$SIGN_KEY" --signed-at "$at"
    fi
}

# 거부해야 하는 것을 **거부(종료 5)** 로 끝내는가. 종료 코드까지 댄다 — 앵커가 없을 때의
# 4 처럼 다른 이유로 실패해도 '거부했다' 로 보이면 이 확인은 아무것도 재지 않는다.
expect_rejected() {
    local exe=$1 dir=$2 what=$3 rc=0
    "$exe" plugin verify --dir "$dir" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 5 ]; then
        echo "::error::$what: 종료 $rc — 5(거부)여야 한다"
        exit 1
    fi
    echo "$what: 거부했다(종료 5)"
}

verify() {
    local exe=${1:?remedy 실행 파일} dir=${2:?플러그인 폴더}
    local name
    name=$(basename "$dir")

    # 1) 박힌 앵커로 확인한다 — --public-key 를 주지 않는다.
    "$exe" plugin verify --dir "$dir"

    # 2) 링크된 엔진이 도는가(yara-x 포함).
    "$exe" selftest | tee "$KEYS/selftest.txt"
    tr -d '\r' <"$KEYS/selftest.txt" | grep -qx 'selftest OK'

    # 3) 반대 확인 — 폴더 이름은 그대로 두고 자리만 옮긴 사본으로.
    rm -rf "$KEYS/tampered" "$KEYS/other"
    mkdir -p "$KEYS/tampered" "$KEYS/other"
    cp -R "$dir" "$KEYS/tampered/$name"
    printf '\n# changed after signing\n' >>"$KEYS/tampered/$name/plugin.yaml"
    expect_rejected "$exe" "$KEYS/tampered/$name" "서명 뒤 고친 룰"

    throwaway other
    cp -R "$dir" "$KEYS/other/$name"
    REMEDY_SIGN_PASSWORD=$(cat "$KEYS/other.pass") cargo xtask sign plugin \
        --dir "$KEYS/other/$name" --secret-key "$KEYS/other.key" \
        --signed-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
    expect_rejected "$exe" "$KEYS/other/$name" "다른 키로 서명한 룰"
}

readme() {
    local f=${1:?README.txt}
    if ! grep -qF '이 바이너리에는 신뢰 앵커가 박혀 있습니다.' "$f"; then
        echo "::error::$f 가 앵커 판 문구가 아니다"
        exit 1
    fi
    if grep -qF '신뢰 앵커가 박혀 있지 않습니다' "$f"; then
        echo "::error::$f 가 앵커가 없다고 적는다"
        exit 1
    fi
    echo "README: 앵커 판"
}

cmd=${1:-}
[ $# -gt 0 ] && shift
case "$cmd" in
pubkey) pubkey ;;
sign) sign "$@" ;;
verify) verify "$@" ;;
readme) readme "$@" ;;
*)
    echo "쓰는 법: ci/release.sh pubkey | sign <폴더> | verify <remedy> <폴더> | readme <README.txt>" >&2
    exit 2
    ;;
esac
