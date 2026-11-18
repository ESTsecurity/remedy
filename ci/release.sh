#!/usr/bin/env bash
#
# 배포 잡(`.github/workflows/release.yml`)의 두 OS 가 함께 쓰는 단계 — 키 · 서명 · 검증.
#
#   ci/release.sh pubkey                         공개키를 준비하고 REMEDY_TRUST_ANCHOR 를 잡의 환경에
#   ci/release.sh sign <플러그인 폴더>             그 키로 서명한다(서명 시각은 이 커밋의 시각)
#   ci/release.sh sign-companion <remedy-net 폴더> 동반 프로그램의 폴더를 같은 키로 서명한다
#   ci/release.sh verify <remedy> <플러그인 폴더>  박힌 앵커로 확인하고, 거부할 것을 거부하는가
#   ci/release.sh verify-companion <remedy>      꾸러미에서 본체가 동반 프로그램을 띄우는가 · 바뀐 것은 안 띄우는가
#   ci/release.sh readme <README.txt>            꾸러미의 안내문이 앵커 판인가
#   ci/release.sh handover <지은 폴더>            (Windows 첫 걸음) 지은 실행 파일 둘을 코드서명에 넘긴다 — 초안에 unsigned-*
#   ci/release.sh fetch-signed <받을 폴더>        (Windows 둘째 걸음) 넘긴 것과 서명본을 받아 서명만 더했는지 잰다
#   ci/release.sh clear-handover                 (Windows 둘째 걸음) 초안에서 넘긴 파일 넷을 지운다
#
# # 키는 어디서 오는가
#
# 배포 태그(`v*` · `rules-*`)의 실행 — 태그 push(첫 걸음)와 같은 태그에서 다시 부른 둘째 걸음(`workflow_dispatch`) —
# 은 Environment `release` 의 비밀로 서명하고 저장소 변수의 공개키를 박는다. PR 의 시험 실행은 그 자리에서 만든
# **일회용 키**로 같은 차례를 돈다 — 비밀을 쓰지 않고, 아무것도 올리지 않는다.
#
# # 코드서명에 넘기는 파일
#
# Windows 실행 파일의 코드서명은 잡 밖(서명하는 기계)에서 한다(`.github/workflows/release.yml` 첫머리). 넘기는 자리는
# 그 태그의 **초안**이다 — Actions 산출물은 공개 저장소에서 로그인한 누구나 받는다. 이름은 `unsigned-<실행 파일>` ·
# `signed-<실행 파일>` 이고 서명하는 쪽(`testbed/harness/host/Invoke-ReleaseCodeSign.ps1`)도 같은 이름을 쓴다.
#
# 비밀은 `sign` 한 단계에만 들어오고 개인키 파일은 그 단계가 끝나면 지운다. 키 파일은
# 저장소 밖(`$RUNNER_TEMP`)에 둔다 — 작업 트리에 두면 꾸러미나 올리는 파일에 섞일 수 있다.
set -euo pipefail

base=${RUNNER_TEMP:?RUNNER_TEMP 가 없다 — 잡 안에서 부를 것}
command -v cygpath >/dev/null 2>&1 && base=$(cygpath -u "$base")
KEYS="$base/remedy-keys"
SIGN_KEY="$KEYS/sign.key"
SIGN_PUB="$KEYS/sign.pub"

# 배포 실행인가 — 태그 push(첫 걸음) · 배포 태그에서 다시 부른 둘째 걸음. PR 의 시험 실행이 아니다.
tagged() {
    case "${GITHUB_EVENT_NAME:-}" in
    push) return 0 ;;
    workflow_dispatch) [[ "${GITHUB_REF:-}" == refs/tags/v* || "${GITHUB_REF:-}" == refs/tags/rules-* ]] ;;
    *) return 1 ;;
    esac
}

# 코드서명에 넘기는 실행 파일 — 이름은 서명하는 쪽 스크립트와 같아야 한다.
CODESIGN_BINS=(remedy.exe remedy-net.exe)

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

# 폴더 하나를 서명한다 — <무엇>은 `cargo xtask sign` 의 하위 명령(plugin · companion)이다.
sign_as() {
    local what=${1:?plugin|companion} dir=${2:?서명할 폴더}
    local at
    at=$(date -u -d "@$(git log -1 --format=%ct)" +%Y-%m-%dT%H:%M:%SZ)
    if tagged; then
        if [ -z "${SECRET_KEY:-}" ] || [ -z "${SECRET_PASSWORD:-}" ]; then
            echo "::error::서명 비밀이 없다 — Environment release 에서 도는 잡인가"
            exit 1
        fi
        trap 'rm -f "$SIGN_KEY"' EXIT
        printf '%s\n' "$SECRET_KEY" >"$SIGN_KEY"
        REMEDY_SIGN_PASSWORD=$SECRET_PASSWORD cargo xtask sign "$what" \
            --dir "$dir" --secret-key "$SIGN_KEY" --signed-at "$at"
    else
        REMEDY_SIGN_PASSWORD=$(cat "$KEYS/sign.pass") cargo xtask sign "$what" \
            --dir "$dir" --secret-key "$SIGN_KEY" --signed-at "$at"
    fi
}

sign() { sign_as plugin "${1:?플러그인 폴더}"; }

# 동반 프로그램(remedy-net)의 폴더 — 본체가 띄우기 전에 확인하는 서명이다. 룰과 같은 키 · 같은 형식.
sign_companion() { sign_as companion "${1:?remedy-net 폴더}"; }

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

# 네트워크 점검 룰 하나로 본체를 띄워 종료 코드를 받는다 — 주소는 이 기계의 닫힌 포트다(밖으로 나가는
# 요청이 없다). 룰은 그 자리에서 만든다: 명령줄은 룰의 서명을 묻지 않고, 여기서 재는 것은 **동반
# 프로그램의 서명**이다.
net_check() {
    local exe=$1 out=$2 rc=0
    mkdir -p "$KEYS/netrule"
    cat >"$KEYS/netrule/plugin.yaml" <<'EOF'
schema_version: 1
id: release-net-probe
version: 0.0.1
min_core: "1.4.0"
platforms: [windows, linux]
name: { ko: "배포 확인", en: "release probe" }
kind: check
network: url
scan_roots: []
subjects: []
detect: []
EOF
    rm -rf "$out"
    "$exe" scan --plugin "$KEYS/netrule/plugin.yaml" --out-dir "$out" \
        --url http://127.0.0.1:9/ --consent y >"$KEYS/net.txt" 2>&1 || rc=$?
    tr -d '\r' <"$KEYS/net.txt" | tail -n 6
    return "$rc"
}

# 받는 사람이 푸는 그 폴더에서 — 본체가 **서명이 맞는 동반 프로그램을 띄우고, 다른 것은 띄우지 않는가.**
verify_companion() {
    local exe=${1:?꾸러미 안의 remedy 실행 파일}
    local pkg name rc
    pkg=$(dirname "$exe")
    name=$(basename "$exe")

    # 1) 띄운다 — 닫힌 포트라 '연결 거부 → 확인 필요(6)' 가 정상이다. 6 은 동반 프로그램이 낸 코드를
    #    본체가 그대로 돌려준 것이다(띄우지 못했으면 5 다). 결과 파일도 그 프로그램이 쓴다.
    rc=0
    net_check "$exe" "$KEYS/netout" || rc=$?
    if [ "$rc" -ne 6 ]; then
        echo "::error::네트워크 점검: 종료 $rc — 6(확인 필요)이어야 한다"
        exit 1
    fi
    if ! ls "$KEYS/netout"/remedy-net-url-*.json >/dev/null 2>&1; then
        echo "::error::동반 프로그램이 결과 파일을 쓰지 않았다"
        exit 1
    fi
    echo "동반 프로그램: 띄웠다(종료 6 · 결과 파일)"

    # 2) 반대 확인 — 꾸러미의 사본에서 동반 프로그램만 바꾼다. 띄우지 않고 5 로 끝나야 한다.
    local case
    for case in tampered otherkey absent; do
        rm -rf "$KEYS/pkg-$case"
        mkdir -p "$KEYS/pkg-$case"
        cp "$exe" "$KEYS/pkg-$case/$name"
        cp -R "$pkg/remedy-net" "$KEYS/pkg-$case/remedy-net"
    done
    printf 'x' >>"$KEYS/pkg-tampered/remedy-net/$(ls "$pkg/remedy-net" | grep -E '^remedy-net(\.exe)?$')"
    throwaway other
    REMEDY_SIGN_PASSWORD=$(cat "$KEYS/other.pass") cargo xtask sign companion \
        --dir "$KEYS/pkg-otherkey/remedy-net" --secret-key "$KEYS/other.key" \
        --signed-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >/dev/null
    rm -rf "$KEYS/pkg-absent/remedy-net"
    for case in tampered otherkey absent; do
        rc=0
        net_check "$KEYS/pkg-$case/$name" "$KEYS/netout-$case" >/dev/null || rc=$?
        if [ "$rc" -ne 5 ]; then
            echo "::error::동반 프로그램($case): 종료 $rc — 5(띄우지 않음)여야 한다"
            exit 1
        fi
        if [ -e "$KEYS/netout-$case" ]; then
            echo "::error::동반 프로그램($case): 띄우지 않았는데 결과 폴더가 생겼다"
            exit 1
        fi
        echo "동반 프로그램($case): 띄우지 않았다(종료 5)"
    done
}

readme() {
    local f=${1:?README.txt}
    if ! grep -qF '이 실행 파일에는 룰 서명을 확인하는 ESTsecurity 공개키가 들어 있습니다.' "$f"; then
        echo "::error::$f 가 앵커 판 문구가 아니다"
        exit 1
    fi
    if grep -qF '신뢰 앵커가 박혀 있지 않습니다' "$f"; then
        echo "::error::$f 가 앵커가 없다고 적는다"
        exit 1
    fi
    echo "README: 앵커 판"
}

# 공개된 Release 에는 손대지 않는다 — 넘기고 받는 자리는 그 태그의 초안뿐이다.
draft_only() {
    local state
    tagged || { echo "::error::코드서명에 넘기고 받는 것은 배포 태그의 실행에서만 한다"; exit 1; }
    state=$(gh release view "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" --json isDraft --jq .isDraft 2>/dev/null || echo none)
    if [ "$state" != true ]; then
        echo "::error::$GITHUB_REF_NAME 의 초안이 없다($state) — 공개된 Release 는 건드리지 않는다"
        exit 1
    fi
}

# 이름을 먼저 다 받고 고른다 — `gh … | grep -q` 는 grep 이 먼저 끝나면 pipefail 아래에서 '없다' 로 읽힐 수 있다.
has_asset() {
    local names
    names=$(gh release view "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" --json assets --jq '.assets[].name' | tr -d '\r')
    grep -qxF "$1" <<<"$names"
}

# (Windows 첫 걸음의 끝) 지은 실행 파일 둘을 초안에 넘긴다. 첫 걸음을 다시 돌렸으면 앞 회차의 서명본(signed-*)을
# 먼저 지운다 — 남겨 두면 둘째 걸음이 새로 지은 것과 견주어 멈추지만, 어느 쪽이 낡았는지 헷갈리게 한다.
handover() {
    local dir=${1:?지은 폴더} out="$base/handover" b
    draft_only
    rm -rf "$out"
    mkdir -p "$out"
    for b in "${CODESIGN_BINS[@]}"; do
        cp "$dir/$b" "$out/unsigned-$b"
        if has_asset "signed-$b"; then
            gh release delete-asset "$GITHUB_REF_NAME" "signed-$b" --repo "$GITHUB_REPOSITORY" --yes
        fi
    done
    (cd "$out" && sha256sum unsigned-*)
    gh release upload "$GITHUB_REF_NAME" "$out"/unsigned-* --repo "$GITHUB_REPOSITORY" --clobber
    echo "코드서명에 넘겼다 — 다음: 서명하는 기계에서 testbed/harness/host/Invoke-ReleaseCodeSign.ps1 -Tag $GITHUB_REF_NAME"
}

# (Windows 둘째 걸음의 시작) 넘긴 것과 서명본을 받아, 서명본이 넘긴 그 파일에 서명만 더한 것인지 바이트로 잰다
# (`cargo xtask codesign`). 맞으면 서명본을 <받을 폴더>/<실행 파일> 에 두고 다음 단계에 BIN_DIR 로 알린다. 서명이
# 유효한지 · 우리 것인지는 다음 단계(OS 의 확인)가 본다.
fetch_signed() {
    local dir=${1:?받을 폴더} got="$base/codesign-fetched" b
    local pats=()
    draft_only
    rm -rf "$got" "$dir"
    mkdir -p "$got" "$dir"
    for b in "${CODESIGN_BINS[@]}"; do pats+=(--pattern "unsigned-$b" --pattern "signed-$b"); done
    gh release download "$GITHUB_REF_NAME" --repo "$GITHUB_REPOSITORY" --dir "$got" "${pats[@]}"
    for b in "${CODESIGN_BINS[@]}"; do
        if [ ! -f "$got/unsigned-$b" ] || [ ! -f "$got/signed-$b" ]; then
            echo "::error::초안에 unsigned-$b · signed-$b 가 함께 있어야 한다 — 코드서명 걸음(Invoke-ReleaseCodeSign.ps1)을 먼저"
            exit 1
        fi
        cargo xtask codesign "$got/unsigned-$b" "$got/signed-$b"
        cp "$got/signed-$b" "$dir/$b"
    done
    (cd "$dir" && sha256sum "${CODESIGN_BINS[@]}")
    echo "BIN_DIR=$dir" >>"${GITHUB_ENV:?}"
}

# (Windows 둘째 걸음의 끝) 넘긴 파일 넷을 초안에서 지운다 — 공개할 초안에는 자산 셋만 남는다(체크섬 잡이 잰다).
clear_handover() {
    local b
    draft_only
    for b in "${CODESIGN_BINS[@]}"; do
        gh release delete-asset "$GITHUB_REF_NAME" "unsigned-$b" --repo "$GITHUB_REPOSITORY" --yes
        gh release delete-asset "$GITHUB_REF_NAME" "signed-$b" --repo "$GITHUB_REPOSITORY" --yes
    done
    echo "코드서명에 넘긴 파일 넷을 초안에서 지웠다"
}

cmd=${1:-}
[ $# -gt 0 ] && shift
case "$cmd" in
pubkey) pubkey ;;
sign) sign "$@" ;;
sign-companion) sign_companion "$@" ;;
verify) verify "$@" ;;
verify-companion) verify_companion "$@" ;;
readme) readme "$@" ;;
handover) handover "$@" ;;
fetch-signed) fetch_signed "$@" ;;
clear-handover) clear_handover ;;
*)
    echo "쓰는 법: ci/release.sh pubkey | sign <폴더> | sign-companion <폴더> | verify <remedy> <폴더> | verify-companion <remedy> | readme <README.txt> | handover <지은 폴더> | fetch-signed <받을 폴더> | clear-handover" >&2
    exit 2
    ;;
esac
