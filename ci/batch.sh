#!/bin/bash
# 룰만 바뀐 출시를 묶어 낸다 — 명령 하나와 승인 한 번(2026-11-21 · 목표 remedy_하루30건_대응체계 차례 2 · docs/긴급-대응.md).
#
#   bash ci/batch.sh [--rc]              main 의 머리를 묶어 낸다 — 룰 버전 → 태그 → 초안 → 필수 점검 → 승인 → 공개
#   bash ci/batch.sh status              지금 Latest · 진행 중인 출시 · 다음 묶음에 들 조각 · 멈춤 이슈
#   bash ci/batch.sh publish <태그>      이미 올라온 초안을 이어 낸다 — 필수 점검 → 승인 → 공개
#   bash ci/batch.sh approve <태그>      승인 대기(종료 3)에서 잇는다 — 점검한 그 파일로 공개(카드로 받은 승인 뒤)
#   bash ci/batch.sh clean <태그>        실패한 초안을 지운다(태그는 남는다 — 다음 묶음은 다음 룰 버전을 쓴다)
#   bash ci/batch.sh views               하루 한 번 — 생성물(README 두 표 · 업데이트 내역 · 하네스 표)을 PR 하나로 갈아 끼운다
#   bash ci/batch.sh engine-tag <v태그>  엔진 출시의 주석 태그(메시지 '프로그램 <엔진> · 룰 <룰 버전>')를 짓고 민다
#   bash ci/batch.sh selftest            다음 룰 버전 · 시험판 번호 · 자산 목록의 갈래를 망 없이 합성 값으로 시험한다(CI)
#
# 누가 · 어디서 — 조직 Owner 가 저장소 루트에서. git · gh(로그인) · bash · cargo 가 있으면 어느 PC 든 묶음 · 태그 · 공개까지
# 간다. 필수 점검은 차례 3(검증을 PC 밖으로) 전까지 리눅스 몫이 docker(Windows 면 WSL), Windows 몫이 랩 VM 이 있는 PC 에서
# 돈다 — 없으면 그 자리에서 멈추고 무엇이 모자라는지 적는다(그때는 그 PC 에서 `publish <태그>` 로 잇는다).
#
# 사람이 하는 것은 이 명령과 마지막의 승인(y) 하나다(결정 D — 출시마다 사람 한 번). 작업자가 터미널 없이 돌리면 점검까지 하고
# 승인 대기(종료 3)로 멈춘다 — 사람이 결과를 보고 승인하면(카드) 작업자가 `approve <태그>` 로 잇는다. 공개 자체는 GitHub 의
# `.github/workflows/publish.yml` 이 한 번에 하나씩 한다 — 최종 확인(자산 = 점검한 파일 · Latest 가 조상 · 엔진 역행 없음) ·
# 공개 · 180초 뒤 익명 확인 · 룰마다 보인 시간(PR 을 연 때 → 공개 · 60분을 넘으면 '모아 내기 멈춤' 이슈).
#
# 묶음 = 그때의 origin/main 머리다. 바뀐 내용은 지금 Latest 의 트리에 없고 그 커밋에 있는 업데이트 내역 조각이고, 룰 버전은
# 한국 날짜(같은 날 둘째부터 꼬리 .N)다. 셋이 같은 이름을 노려도 태그 만들기가 원자적이라 하나만 서고, 진 쪽은 다음 이름으로
# 다시 민다. 한 번에 한 묶음만 간다 — 초안이 남아 있으면 시작하지 않는다(엔진 출시의 초안이면 룰 공개를 멈춘다 · 결정 R2).
set -euo pipefail

die() { echo "batch: $*" >&2; exit 1; }
say() { echo "batch: $*"; }

RULES_RE='[0-9]{4}\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])(\.([2-9]|[1-9][0-9]+))?'

# ── 판단(망 없이 — selftest 가 시험한다) ───────────────────────────────────────────────────────────

# b 가 a 보다 높은가(점으로 가른 수).
higher() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$2" ]; }

# 다음 룰 버전 — next_rules_version <Latest 의 룰 버전> <오늘 YYYY.MM.DD> <이미 쓴 룰 버전…>
# 오늘(Latest 의 날이 더 늦으면 그날)의 맨 이름부터 꼬리 .2 · .3 … 으로, 이미 쓴 것(태그 · 시험판 · 엔진 출시의 메시지)과
# Latest 이하를 건너뛴 첫 것. 꼬리는 세 자리까지(remedy_sdk::rules_version).
next_rules_version() {
    local latest=$1 today=$2 day c n
    shift 2
    day=$today
    higher "${latest:0:10}" "$today" || [ "${latest:0:10}" = "$today" ] || day=${latest:0:10}
    for n in 1 $(seq 2 999); do
        if [ "$n" = 1 ]; then c=$day; else c="$day.$n"; fi
        higher "$latest" "$c" || continue
        printf '%s\n' "$@" | grep -qxF -- "$c" && continue
        echo "$c"
        return 0
    done
    return 1
}

# 시험판 번호 — next_rc <태그> <이미 있는 태그…> : 그 태그의 -rc.N 가운데 다음 N.
next_rc() {
    local tag=$1 n=1
    shift
    while printf '%s\n' "$@" | grep -qxF -- "$tag-rc.$n"; do n=$((n + 1)); done
    echo "$tag-rc.$n"
}

# 태그 이름들에서 쓴 룰 버전 — rules-<V>[-rc.N] 의 V.
rules_of_tags() { sed -nE "s/^rules-($RULES_RE)(-rc\.[0-9]+)?\$/\\1/p"; }

# 자산 목록 — 'name:sha256 …'(publish.yml 의 입력 · 점검한 그 파일).
assets_arg() {
    local d=$1 out="" a
    for a in remedy-linux-x64.tar.gz remedy-windows-x64.zip SHA256SUMS; do
        [ -f "$d/$a" ] || return 1
        out+="$a:$(sha256sum "$d/$a" | cut -d' ' -f1) "
    done
    echo "${out% }"
}

selftest() {
    local pass=0 bad=0
    t() { if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "통과  $1"; else bad=$((bad + 1)); echo "실패  $1 — '$2'(기대 '$3')"; fi; }
    t "오늘의 첫 룰 버전" "$(next_rules_version 2026.11.21 2026.11.22)" 2026.11.22
    t "같은 날 둘째" "$(next_rules_version 2026.11.22 2026.11.22)" 2026.11.22.2
    t "이미 쓴 이름(시험판 · 버린 태그)은 건너뛴다" "$(next_rules_version 2026.11.22 2026.11.22 2026.11.22.2 2026.11.22.3)" 2026.11.22.4
    t "Latest 가 오늘보다 늦으면 그날의 다음" "$(next_rules_version 2026.11.23.2 2026.11.22)" 2026.11.23.3
    t "열째 꼬리" "$(next_rules_version 2026.11.22.9 2026.11.22)" 2026.11.22.10
    t "태그에서 룰 버전" "$(printf '%s\n' rules-2026.11.22 rules-2026.11.22.2-rc.1 v1.25.3 rules-x | rules_of_tags | tr '\n' ' ')" "2026.11.22 2026.11.22.2 "
    t "첫 시험판" "$(next_rc rules-2026.11.22)" rules-2026.11.22-rc.1
    t "다음 시험판" "$(next_rc rules-2026.11.22 rules-2026.11.22-rc.1 rules-2026.11.22-rc.2)" rules-2026.11.22-rc.3
    local d
    d=$(mktemp -d)
    printf a >"$d/remedy-linux-x64.tar.gz"
    printf b >"$d/remedy-windows-x64.zip"
    t "자산이 모자라면 목록을 짓지 않는다" "$(assets_arg "$d" || echo 없음)" 없음
    printf c >"$d/SHA256SUMS"
    t "자산 목록" "$(assets_arg "$d" | tr ' ' '\n' | cut -d: -f1 | tr '\n' ' ')" "remedy-linux-x64.tar.gz remedy-windows-x64.zip SHA256SUMS "
    rm -rf "$d"
    echo "--- 통과 $pass · 실패 $bad"
    [ "$bad" = 0 ]
}

# ── GitHub · 저장소 ───────────────────────────────────────────────────────────────────────────────

repo() { gh repo view --json nameWithOwner --jq .nameWithOwner; }

# 지금 Latest — LATEST · LATEST_ENGINE · LATEST_RULES
load_latest() {
    local got
    got=$(gh release view --json tagName,name --jq '.tagName + "\t" + .name') || die "지금 Latest 를 읽지 못했다(gh 로그인을 볼 것)"
    LATEST=${got%%$'\t'*}
    local name=${got#*$'\t'}
    LATEST_ENGINE=$(sed -nE 's/^프로그램 ([0-9]+\.[0-9]+\.[0-9]+) · 룰 (.*)$/\1/p' <<<"$name")
    LATEST_RULES=$(sed -nE 's/^프로그램 ([0-9]+\.[0-9]+\.[0-9]+) · 룰 (.*)$/\2/p' <<<"$name")
    [ -n "$LATEST_ENGINE" ] && [ -n "$LATEST_RULES" ] || die "Latest $LATEST 의 이름 '$name' 이 '프로그램 <엔진> · 룰 <룰>' 꼴이 아니다"
}

# 도구가 최신인가(기준 5(나)) — 이 사본의 도구가 origin/main 과 같아야 한다. 낡은 하네스 · 스크립트로 재고 내지 않는다.
fresh_tools() {
    git fetch -q --tags origin main || die "git fetch 가 안 된다"
    if ! git diff --quiet origin/main -- ci testbed/harness .github xtask; then
        die "이 사본의 도구(ci · testbed/harness · .github · xtask)가 origin/main 과 다르다 — git switch main && git pull --ff-only 뒤 다시"
    fi
}

hold_issue() {
    gh issue list --state open --search '"모아 내기 멈춤" in:title' --json number,title --jq '.[] | "#\(.number) \(.title)"'
}

drafts() { gh release list --limit 30 --json tagName,isDraft --jq '.[] | select(.isDraft) | .tagName'; }

# 그 태그의 release.yml push 실행을 끝까지 본다.
wait_release_run() {
    local tag=$1 id="" i
    for i in $(seq 1 30); do
        id=$(gh run list --workflow release.yml --event push --limit 20 --json databaseId,headBranch \
            --jq ".[] | select(.headBranch == \"$tag\") | .databaseId" | head -1)
        [ -n "$id" ] && break
        sleep 5
    done
    [ -n "$id" ] || die "$tag 의 배포 실행을 찾지 못했다"
    say "배포 실행 $id 를 기다린다(태그 → 자산 셋 약 4 ~ 5분)"
    gh run watch "$id" --exit-status --interval 15 >/dev/null || die "배포 실행 $id 가 실패했다 — gh run view $id --log-failed · 고친 뒤 bash ci/batch.sh clean $tag 로 초안을 치우고 다시"
}

# 초안의 자산을 받아 잰다 — <폴더>/{자산 셋} · win/ · linux/ 에 푼다.
fetch_draft() {
    local tag=$1 d=$2
    rm -rf "$d"
    mkdir -p "$d/win" "$d/linux"
    gh release download "$tag" --dir "$d" >/dev/null
    (cd "$d" && sha256sum -c SHA256SUMS) || die "$tag 초안의 체크섬이 맞지 않는다"
    unzip -q "$d/remedy-windows-x64.zip" -d "$d/win"
    tar -xzf "$d/remedy-linux-x64.tar.gz" -C "$d/linux"
}

# ── 필수 점검(docs/긴급-대응.md ①~⑤) ─────────────────────────────────────────────────────────────

on_windows() { case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) return 0 ;; *) return 1 ;; esac; }
# Git Bash 의 경로를 WSL 의 경로로(드라이브 글자 → WSL 의 /mnt/<드라이브> 자리 · 소문자). wslpath 는 쓰지 않는다 — Docker
# Desktop 이 저장소 폴더를 묶어 둔 기계에서는 그 묶음 자리(/mnt/wsl/docker-desktop-bind-mounts/…)를 돌려준다(2026-11-21 에 쟀다).
to_wsl() { local p; p=$(cd "$1" && pwd -W); echo "/mnt/${p:0:1}${p:2}" | sed 's|^/mnt/\(.\)|/mnt/\L\1|'; }

# 묶음에서 판정이 바뀔 수 있는 룰 폴더(지금 Latest 대비) — 서명 파일과 출시 기록(RELEASE.md)만 바뀐 룰은 빼고 따로 센다
# (잠금 검사 `plugin-lock` 과 같은 잣대 — 판정을 정하는 것은 plugin.yaml · rules/ · 데이터 룰의 데이터 파일이다).
changed_rules() {
    git diff --name-only "$LATEST" "$1" -- plugins ':!plugins/*/MANIFEST' ':!plugins/*/MANIFEST.minisig' \
        ':!plugins/*/RELEASE.md' | awk -F/ 'NF >= 3 { print $2 }' | sort -u
}
records_only() {
    comm -23 <(git diff --name-only "$LATEST" "$1" -- 'plugins/*/RELEASE.md' | awk -F/ '{ print $2 }' | sort -u) \
        <(changed_rules "$1")
}

# 리눅스 룰 하네스 — 머리의 `# 룰:` 줄이 그 룰을 적은 것.
harness_of() {
    local id=$1 f
    for f in testbed/harness/linux/*.sh; do
        if sed -n '1,10p' "$f" | grep -qE "^# 룰: .*(^|[ ,])$id([ ,—]|$)"; then
            echo "$f"
            return 0
        fi
    done
    return 1
}

checks() {
    local tag=$1 commit=$2 d=$3 notes=()
    say "필수 점검 — 지난 공개본 $LATEST 의 꾸러미를 받는다"
    fetch_draft "$LATEST" "$d/prev"
    # ① 바뀐 리눅스 룰의 하네스 · G9 재료(.yar 바이트)
    local harness=() id plat yar_changed=()
    while IFS= read -r id; do
        # 묶음의 커밋에 있는 룰만 — 지운 룰은 그 커밋에 없다(없는 자리를 git show 하면 set -e 아래에서 그대로 멈춘다).
        [ -n "$id" ] && git cat-file -e "$commit:plugins/$id/plugin.yaml" 2>/dev/null || continue
        plat=$(git show "$commit:plugins/$id/plugin.yaml" | sed -n 's/^platforms: *\[\(.*\)\].*/\1/p')
        if [[ "$plat" == *linux* ]]; then
            if h=$(harness_of "$id"); then
                printf '%s\n' "${harness[@]:-}" | grep -qxF -- "$h" || harness+=("$h")
            else
                notes+=("① $id 의 리눅스 하네스가 없다(머리의 '# 룰:' 줄) — ③ 기존 동작과 24시간 안의 rc 묶음이 본다")
            fi
        fi
        if [[ "$plat" == *windows* ]]; then
            notes+=("① $id(Windows) 의 하네스는 차례 3 전까지 이 명령이 돌리지 않는다 — 그 룰의 PR 전 하네스 기록을 승인 전에 본다")
        fi
        for y in $(git -c core.quotePath=false ls-tree -r --name-only "$commit" -- "plugins/$id/rules" | grep '\.yar$' || true); do
            local a b=""
            a=$(git show "$commit:$y" | sha256sum | cut -d' ' -f1)
            # Latest 에 없는 .yar(새 룰 · 더한 규칙)는 b 가 비어 바뀐 것으로 센다 — 없는 자리를 git show 하면 128 이라 먼저
            # 묻는다(전에는 set -e 아래 그 대입에서 메시지 없이 멈춰 YARA 가 든 새 룰의 묶음을 낼 수 없었다 · 반박 검토).
            if git cat-file -e "$LATEST:$y" 2>/dev/null; then b=$(git show "$LATEST:$y" | sha256sum | cut -d' ' -f1); fi
            [ "$a" = "$b" ] || yar_changed+=("$y")
        done
    done < <(changed_rules "$commit")
    local rec
    rec=$(records_only "$commit" | tr '\n' ' ')
    [ -z "$rec" ] || notes+=("① 출시 기록(RELEASE.md)만 바뀐 룰 — 판정이 그대로라 하네스를 돌리지 않았다: $rec")
    # ④ G9 — YARA 가 바뀐 룰이 있으면 코퍼스를 잰 기록(G9_DONE)이 있어야 하고, 그 기록에 초안 꾸러미의 그 .yar 의 sha256 이
    # 적혀 있어야 한다 — 잰 .yar 와 공개할 .yar 가 같은 바이트인지 여기서 견준다(docs/긴급-대응.md ④). 이 명령은 잰 결과를
    # 대신 만들지 않는다.
    if [ ${#yar_changed[@]} -gt 0 ]; then
        [ -n "${G9_DONE:-}" ] && [ -f "$G9_DONE" ] ||
            die "④ G9 — YARA 가 바뀐 룰이 있다: ${yar_changed[*]} — cargo xtask yara 로 정상 파일 코퍼스를 재고, 잰 .yar 의 sha256(sha256sum plugins/<룰>/rules/*.yar)을 그 기록에 적은 뒤 G9_DONE=<기록 파일> bash ci/batch.sh publish $tag"
        local p base hy
        for y in "${yar_changed[@]}"; do
            p=""
            for base in "$d/linux/remedy-linux-x64" "$d/win/remedy-windows-x64"; do
                if [ -f "$base/$y" ]; then p="$base/$y"; break; fi
            done
            [ -n "$p" ] || die "④ G9 — 초안 꾸러미에 $y 가 없다"
            hy=$(sha256sum "$p" | cut -d' ' -f1)
            grep -qi -- "$hy" "$G9_DONE" || die "④ G9 — 기록 $G9_DONE 에 초안의 $y(sha256 $hy)가 없다 — G9 를 잰 .yar 와 다를 수 있다"
        done
        notes+=("④ G9 — YARA 가 바뀐 룰 ${#yar_changed[@]}개 · 초안의 .yar 가 기록 $G9_DONE 의 sha256 과 같다")
    else
        notes+=("④ G9 — 바뀐 룰의 YARA 가 지금 Latest 와 같은 바이트다(또는 YARA 가 없다)")
    fi

    # ①②③ 리눅스 — docker(Windows 면 WSL).
    local hargs=() h
    if [ ${#harness[@]} -eq 0 ]; then hargs=(--harness none); else for h in "${harness[@]}"; do hargs+=(--harness "$h"); done; fi
    say "필수 점검 — 리눅스(하네스 ${#harness[@]}개 · 정식 파일 · 기존 동작)"
    local rel_new rel_prev rel_out
    rel_new=${d#"$PWD"/}/remedy-linux-x64.tar.gz
    rel_prev=${d#"$PWD"/}/prev/remedy-linux-x64.tar.gz
    rel_out=${d#"$PWD"/}/linux-checks
    if on_windows; then
        command -v wsl.exe >/dev/null || die "리눅스 필수 점검에 WSL(docker)이 필요하다"
        MSYS_NO_PATHCONV=1 wsl.exe --cd "$(to_wsl "$PWD")" -e bash testbed/harness/linux/emergency-checks.sh \
            --new "$rel_new" --prev "$rel_prev" --out "$rel_out" "${hargs[@]}" ||
            die "리눅스 필수 점검이 실패했다 — $rel_out/summary.txt"
        # 무거운 WSL 일 뒤에는 다음 일을 띄우기 전에 캐시를 비운다(랩과 겹치면 메모리가 모자랐다).
        wsl.exe -u root -e sh -c 'echo 3 > /proc/sys/vm/drop_caches' || true
    else
        bash testbed/harness/linux/emergency-checks.sh --new "$rel_new" --prev "$rel_prev" --out "$rel_out" "${hargs[@]}" ||
            die "리눅스 필수 점검이 실패했다 — $rel_out/summary.txt"
    fi

    # ②③ Windows — 랩 VM(차례 3 전까지 이 PC).
    if on_windows && [ -f .cargo/windows_lab.yml ]; then
        say "필수 점검 — Windows(정식 파일 · 시연 게이트 · 메뉴 하네스 · 되돌리기 · 약 7분)"
        powershell.exe -NoProfile -ExecutionPolicy Bypass -File testbed/harness/host/Invoke-EmergencyChecks.ps1 \
            -Package "$(cd "$d/win/remedy-windows-x64" && pwd -W)" -Prev "$(cd "$d/prev/win/remedy-windows-x64" && pwd -W)" \
            -LogDir "$(mkdir -p "$d/windows-checks" && cd "$d/windows-checks" && pwd -W)" >"$d/windows-checks.log" 2>&1 ||
            die "Windows 필수 점검이 실패했다 — ${d#"$PWD"/}/windows-checks/summary.txt"
    else
        die "Windows 필수 점검을 돌릴 랩이 이 PC 에 없다(.cargo/windows_lab.yml) — 랩이 있는 PC 에서 bash ci/batch.sh publish $tag 로 잇는다"
    fi

    echo
    echo "── 필수 점검 결과 ─────────────────────────────────────────"
    cat "$d/linux-checks/summary.txt"
    tr -d '\r' <"$d/windows-checks/summary.txt"
    local f
    for f in "$d"/linux-checks/scan-all/*.diff; do
        [ -s "$f" ] || continue
        echo "③ 화면 차이 $(basename "$f") — 새 룰의 줄 · 룰 버전 줄뿐인지 본다:"
        sed -n '1,40p' "$f"
    done
    printf '%s\n' "${notes[@]}"
}

# 점검을 마친 표지 — 승인 걸음(approve)이 이것으로 '점검한 그 파일' 인지 본다. 점검이 모두 지난 뒤에만 쓴다.
mark_checked() { { echo "$1"; assets_arg "$2"; } >"$2/checked.txt"; }

# 승인 한 번(결정 D). 터미널이면 y/N 을 묻는다. 터미널이 아니면(작업자가 돌린 셸) 승인을 기다리며 종료 3 으로 멈춘다 —
# 사람이 결과를 보고 승인하면(카드) 작업자가 `bash ci/batch.sh approve <태그>` 로 잇는다. 그 뒤 공개 워크플로를 부르고 끝까지 본다.
approve_and_publish() {
    local tag=$1 d=$2 dry=$3 approved=${4:-} assets ans id i x
    assets=$(assets_arg "$d") || die "점검한 자산 셋이 없다($d)"
    if [ "$dry" = false ] && [ "$approved" != approved ]; then
        if [ ! -t 0 ]; then
            say "승인을 기다린다 — $tag 는 초안 그대로다. 위 필수 점검 결과 · 화면 차이를 사람이 보고 승인하면:"
            say "  bash ci/batch.sh approve $tag      (공개하지 않으려면 bash ci/batch.sh clean $tag)"
            exit 3
        fi
        echo
        read -r -p "$tag 를 공개할까요? 필수 점검 결과 · 화면 차이를 봤다면 y (y/N) " ans
        [ "$ans" = y ] || die "공개하지 않았다 — 초안은 그대로다(bash ci/batch.sh approve $tag 로 다시 · clean $tag 로 치운다)"
    fi
    # 부르기 전에 있던 실행을 적어 둔다 — 같은 태그를 전에 부른 실행(시험판의 거듭된 시험 등)을 이 실행으로 잘못 집지 않게.
    local before
    before=" $(gh run list --workflow publish.yml --limit 30 --json databaseId --jq '.[].databaseId' | tr '\n' ' ') "
    gh workflow run publish.yml -f tag="$tag" -f assets="$assets" -f dry_run="$dry" >/dev/null
    id=""
    for i in $(seq 1 30); do
        sleep 4
        for x in $(gh run list --workflow publish.yml --event workflow_dispatch --limit 10 --json databaseId,displayTitle \
            --jq ".[] | select(.displayTitle | contains(\"$tag\")) | .databaseId"); do
            case "$before" in *" $x "*) ;; *) id=$x; break ;; esac
        done
        [ -n "$id" ] && break
    done
    [ -n "$id" ] || die "공개 실행을 찾지 못했다 — gh run list --workflow publish.yml"
    say "공개 실행 $id 를 기다린다($( [ "$dry" = true ] && echo '시험 — 공개하지 않는다' || echo '공개 · 180초 뒤 익명 확인'))"
    gh run watch "$id" --exit-status --interval 15 >/dev/null || die "공개 실행 $id 가 실패했다 — gh run view $id --log"
    say "공개 실행 $id 끝 — $(gh run view "$id" --json conclusion --jq .conclusion)"
}

# ── 명령 ──────────────────────────────────────────────────────────────────────────────────────────

cmd_status() {
    load_latest
    git fetch -q --tags origin main
    echo "지금 Latest: $LATEST (프로그램 $LATEST_ENGINE · 룰 $LATEST_RULES)"
    echo "초안: $(drafts | tr '\n' ' ')"
    echo "멈춤 이슈: $(hold_issue | tr '\n' ' ')"
    echo "origin/main: $(git rev-parse --short origin/main) · Latest 가 조상인가: $(git merge-base --is-ancestor "$LATEST" origin/main && echo 예 || echo 아니오)"
    echo "── 다음 묶음에 들 것(Latest 뒤에 든 조각)"
    cargo xtask changes --since "$LATEST" --head origin/main 2>/dev/null || echo "(없다)"
}

cmd_batch() {
    local rc=$1
    [ -f Cargo.toml ] && [ -f ci/version-check.sh ] || die "저장소 루트에서 부를 것"
    fresh_tools
    load_latest
    local hold
    hold=$(hold_issue)
    [ -z "$hold" ] || die "모아 내기가 멈춰 있다: $hold — 까닭을 적고 닫은 뒤 다시(AGENTS.md · 60분 상한)"
    local pending
    pending=$(drafts)
    if [ -n "$pending" ]; then
        if grep -q '^v' <<<"$pending"; then die "엔진 출시가 진행 중이다($pending) — 그 공개까지 룰 공개를 멈춘다(결정 R2)"; fi
        die "진행 중인 출시가 있다($pending) — 끝내거나(bash ci/batch.sh publish <태그>) 치운다(bash ci/batch.sh clean <태그>)"
    fi
    local commit
    commit=$(git rev-parse origin/main)
    git merge-base --is-ancestor "$LATEST" "$commit" || die "지금 Latest($LATEST)가 origin/main 의 조상이 아니다"
    echo "── 이번 묶음 — origin/main ${commit:0:12} · 지금 Latest $LATEST 뒤에 든 조각:"
    cargo xtask changes --since "$LATEST" --head "$commit" || die "묶을 것이 없다"
    echo
    # 다음 룰 버전 — 이미 쓴 이름(태그 · 시험판 · 엔진 출시의 메시지)을 피한다.
    local used today v tag
    used=$( { git tag -l 'rules-*' | rules_of_tags; git for-each-ref --format='%(contents:subject)' 'refs/tags/v*' |
        sed -nE "s/^프로그램 [0-9.]+ · 룰 ($RULES_RE)\$/\\1/p"; } | sort -u)
    today=$(date -u -d '+9 hours' +%Y.%m.%d)
    v=$(next_rules_version "$LATEST_RULES" "$today" $used) || die "다음 룰 버전을 정하지 못했다"
    tag="rules-$v"
    if [ "$rc" = 1 ]; then tag=$(next_rc "$tag" $(git tag -l "rules-$v-rc.*")); fi
    bash ci/version-check.sh "$tag" --ref "$commit" --prev "$LATEST" --prev-name "프로그램 $LATEST_ENGINE · 룰 $LATEST_RULES"
    git tag "$tag" "$commit"
    if ! git push -q origin "refs/tags/$tag"; then
        git tag -d "$tag" >/dev/null
        die "태그 $tag 를 밀지 못했다(동료가 같은 이름을 먼저 밀었을 수 있다) — git fetch --tags 뒤 다시"
    fi
    say "태그 $tag → ${commit:0:12} 를 밀었다 $(date '+%H:%M:%S')"
    wait_release_run "$tag"
    publish_tail "$tag" "$commit" "$rc"
}

publish_tail() {
    local tag=$1 commit=$2 rc=$3 d
    d="testbed/harness/results/batch/$tag"
    say "초안을 받아 잰다 → $d"
    fetch_draft "$tag" "$d"
    if [[ "$tag" == v* ]]; then
        # 엔진 출시는 평소 경로다 — 공개 전 검증은 rc 의 두 OS rc 묶음과 정식의 최종 확인(docs/개발-안내.md "출시 검증"
        # 4 · 6)이다. 여기서는 그 검증을 다시 돌리지 않고, 승인 뒤 공개 워크플로가 기계 확인 · 공개 · 익명 확인을 한다.
        say "엔진 출시 $tag — 필수 점검 대신 '출시 검증' 4(rc 묶음)를 마쳤고 6(최종 확인)을 이 폴더의 파일($d)로 돌린 뒤 승인한다"
    else
        checks "$tag" "$commit" "$d"
    fi
    mark_checked "$tag" "$d"
    if [ "$rc" = 1 ]; then
        approve_and_publish "$tag" "$d" true
        say "시험판 $tag 의 공개 걸음을 시험했다(공개하지 않았다) — 초안은 bash ci/batch.sh clean $tag 로 치운다"
    else
        approve_and_publish "$tag" "$d" false
    fi
}

cmd_publish() {
    local tag=${1:?태그}
    fresh_tools
    load_latest
    local commit rc=0
    commit=$(git rev-parse "$tag^{commit}") || die "태그 $tag 가 없다"
    [[ "$tag" == *-rc.* ]] && rc=1
    [ "$(gh release view "$tag" --json isDraft --jq .isDraft)" = true ] || die "$tag 는 초안이 아니다"
    publish_tail "$tag" "$commit" "$rc"
}

# 승인 대기(종료 3)에서 잇는다 — 점검을 다시 돌리지 않고, 점검한 그 파일(checked.txt 의 digest)이 지금도 그 폴더에 있는지만 본다.
# 공개 워크플로가 초안의 자산이 그 digest 와 같은지 다시 본다.
cmd_approve() {
    local tag=${1:?태그} d dry=false
    d="testbed/harness/results/batch/$tag"
    fresh_tools
    load_latest
    [ -f "$d/checked.txt" ] || die "$tag 의 점검 기록이 없다($d/checked.txt) — bash ci/batch.sh publish $tag"
    [ "$(sed -n 1p "$d/checked.txt")" = "$tag" ] && [ "$(sed -n 2p "$d/checked.txt")" = "$(assets_arg "$d")" ] ||
        die "점검한 파일이 그 폴더에 그대로가 아니다 — bash ci/batch.sh publish $tag 로 다시 잰다"
    [ "$(gh release view "$tag" --json isDraft --jq .isDraft)" = true ] || die "$tag 는 초안이 아니다"
    [[ "$tag" == *-rc.* ]] && dry=true
    approve_and_publish "$tag" "$d" "$dry" approved
}

cmd_clean() {
    local tag=${1:?태그}
    [ "$(gh release view "$tag" --json isDraft --jq .isDraft 2>/dev/null)" = true ] || die "$tag 는 초안이 아니다 — 공개한 Release 는 지우지 않는다"
    gh release delete "$tag" --yes
    say "초안 $tag 를 지웠다(태그는 남는다 — 다음 묶음은 다음 룰 버전을 쓴다)"
}

cmd_views() {
    [ -z "$(git status --porcelain)" ] || die "작업 트리가 깨끗해야 한다(생성물 PR 을 짓는다)"
    fresh_tools
    local back br tsv
    back=$(git rev-parse --abbrev-ref HEAD)
    br="views/$(date -u -d '+9 hours' +%Y%m%d-%H%M)"
    git switch -q -c "$br" origin/main
    tsv=$(mktemp)
    # 공개한 출시 전부를 준다 — 생성 구간은 조각을 쓴 출시마다 그 앞 출시와 견줘 짓는다. 목록이 조각을 쓴 첫 출시보다 앞까지
    # 닿지 않으면 views 가 멈춘다(잘린 목록의 가장 옛 칸이 조용히 빠지지 않게).
    gh release list --limit 2000 --json tagName,name,publishedAt,isDraft,isPrerelease \
        --jq '[.[] | select(.isDraft | not) | select(.isPrerelease | not)] | sort_by(.publishedAt) | reverse | .[] | [.tagName, .name, .publishedAt] | @tsv' >"$tsv"
    cargo xtask views --write --releases "$tsv"
    rm -f "$tsv"
    if [ -z "$(git status --porcelain)" ]; then
        git switch -q "$back"
        git branch -q -D "$br"
        say "생성물이 이미 같다 — PR 없음"
        return 0
    fi
    git add -A README.md docs testbed/harness/README.md
    git commit -q -m "하루 생성물을 갈아 끼운다 — README 두 표 · 업데이트 내역 · 하네스 표(cargo xtask views --write)"
    git push -q -u origin "$br"
    gh pr create --base main --head "$br" --title "하루 생성물 — $(date -u -d '+9 hours' +%Y-%m-%d)" \
        --body "cargo xtask views --write 가 지은 생성물이다(README 두 표 · 업데이트 내역의 생성 구간 · 하네스 표). 공개한 조각은 업데이트 내역에 옮겨 지웠다."
    local head
    head=$(git rev-parse HEAD)
    sleep 20
    gh pr checks "$br" --watch --interval 30 >/dev/null || die "생성물 PR 의 CI 가 실패했다"
    gh pr merge "$br" --merge --match-head-commit "$head"
    git switch -q "$back"
    say "생성물 PR 을 병합했다"
}

cmd_engine_tag() {
    local tag=${1:?v<엔진 버전>[-rc.N]} engine v base_tag
    [[ "$tag" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)(-rc\.[0-9]+)?$ ]] || die "엔진 태그는 v<X.Y.Z>[-rc.N] 이다"
    engine=${BASH_REMATCH[1]}
    fresh_tools
    load_latest
    # 정식 태그는 그 시험판과 같은 룰 버전을 쓴다(같은 커밋).
    base_tag=$(git tag -l "v$engine-rc.*" | sort -V | tail -1)
    if [ "${tag%-rc.*}" = "$tag" ] && [ -n "$base_tag" ]; then
        v=$(git for-each-ref --format='%(contents:subject)' "refs/tags/$base_tag" | sed -nE "s/^프로그램 [0-9.]+ · 룰 ($RULES_RE)\$/\\1/p")
    fi
    if [ -z "${v:-}" ]; then
        if git diff --quiet "$LATEST" origin/main -- plugins/ ':!plugins/RULES-VERSION' ':!plugins/versions.lock.json' \
            ':!plugins/*/MANIFEST' ':!plugins/*/MANIFEST.minisig'; then
            v=$LATEST_RULES
        else
            local used
            used=$( { git tag -l 'rules-*' | rules_of_tags; git for-each-ref --format='%(contents:subject)' 'refs/tags/v*' |
                sed -nE "s/^프로그램 [0-9.]+ · 룰 ($RULES_RE)\$/\\1/p"; } | sort -u)
            v=$(next_rules_version "$LATEST_RULES" "$(date -u -d '+9 hours' +%Y.%m.%d)" $used) || die "다음 룰 버전을 정하지 못했다"
        fi
    fi
    # 정식 태그는 그 시험판의 커밋에 단다 — rc 묶음 · 최종 확인(rc 와 바이트 대조)이 잰 그 커밋이다. 시험판은 main 머리에.
    local commit=${ENGINE_TAG_REF:-}
    if [ -z "$commit" ] && [ "${tag%-rc.*}" = "$tag" ] && [ -n "$base_tag" ]; then commit=$(git rev-parse "$base_tag^{commit}"); fi
    [ -n "$commit" ] || commit=$(git rev-parse origin/main)
    git tag -a "$tag" -m "프로그램 $engine · 룰 $v" "$commit"
    bash ci/version-check.sh "$tag" --ref "$commit" --prev "$LATEST" --prev-name "프로그램 $LATEST_ENGINE · 룰 $LATEST_RULES" ||
        { git tag -d "$tag" >/dev/null; die "버전 검사가 멈췄다"; }
    git push -q origin "refs/tags/$tag" || { git tag -d "$tag" >/dev/null; die "태그 $tag 를 밀지 못했다"; }
    say "엔진 태그 $tag(프로그램 $engine · 룰 $v) → ${commit:0:12} — 코드서명 걸음: testbed/harness/host/Invoke-ReleaseCodeSign.ps1 -Tag $tag"
}

case "${1:-}" in
    selftest) selftest ;;
    status) cmd_status ;;
    publish) cmd_publish "${2:-}" ;;
    approve) cmd_approve "${2:-}" ;;
    clean) cmd_clean "${2:-}" ;;
    views) cmd_views ;;
    engine-tag) cmd_engine_tag "${2:-}" ;;
    --rc) cmd_batch 1 ;;
    "") cmd_batch 0 ;;
    *) echo "쓰는 법: bash ci/batch.sh [--rc] | status | publish <태그> | approve <태그> | clean <태그> | views | engine-tag <v태그> | selftest" >&2; exit 2 ;;
esac
