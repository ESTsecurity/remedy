#!/bin/bash
# 시스템 상태를 JSON 으로 캡처한다. **remedy 를 전혀 쓰지 않는다.**
#
# Windows 쪽 `guest/Capture-State.ps1` 의 짝이고, 존재 이유도 같다 —
# remedy 의 감사 로그는 **무엇을 하려 했는가**를 말하고, 이 스크립트는
# **실제로 무엇이 바뀌었는가**를 말한다. 둘이 어긋나는 지점이 곧 버그다.
#
# 검증자가 피검증자를 신뢰하면 검증이 아니다. 그래서 여기서는 `remedy` 를
# 부르지 않고 `stat` · `sha256sum` · `readlink` · `pgrep` 만 쓴다.
#
# # 무엇을 담는가
#
# 픽스처가 사는 자리 전부. **지워질 것과 남을 것을 같이 담는다** — 남을 것이
# 빠지면 "계획에 없는 것을 건드렸다" 를 잴 수 없다.
#
# 파일은 존재·크기·해시·모드를 담는다. 해시가 있어야 격리·복원 왕복에서
# **바이트가 같은 것이 돌아왔는가**를 볼 수 있다.
#
# # 쓰는 법
#
#     capture-state.sh > before.json
#     capture-state.sh > after.json

set -u

EXTROOT="${EXTROOT:-$HOME/.config/google-chrome/Default/Extensions}"

# JSON 문자열로 이스케이프한다. 경로에 따옴표나 역슬래시가 들어와도 깨지지
# 않게 한다 — 픽스처 경로에는 없지만, 이 스크립트를 다른 자리에 겨눌 수 있다.
esc() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/\t/\\t/g'
}

# 파일 하나. 없으면 present:false 로 담는다 — 빠뜨리는 것과 없는 것은 다르다.
emit_file() {
    local p="$1"
    if [ -L "$p" ]; then
        printf '    { "path": "%s", "present": true, "kind": "symlink", "target": "%s" }' \
            "$(esc "$p")" "$(esc "$(readlink "$p")")"
    elif [ -f "$p" ]; then
        printf '    { "path": "%s", "present": true, "kind": "file", "size": %s, "mode": "%s", "sha256": "%s" }' \
            "$(esc "$p")" \
            "$(stat -c %s "$p")" \
            "$(stat -c %a "$p")" \
            "$(sha256sum "$p" | cut -d' ' -f1)"
    elif [ -d "$p" ]; then
        printf '    { "path": "%s", "present": true, "kind": "dir", "mode": "%s" }' \
            "$(esc "$p")" "$(stat -c %a "$p")"
    else
        printf '    { "path": "%s", "present": false }' "$(esc "$p")"
    fi
}

# 파일 안의 줄 하나가 있는가. 줄 단위 Op(hosts·text_config)을 재는 자리다.
emit_line() {
    local p="$1" pat="$2" label="$3" n=0
    [ -f "$p" ] && n="$(grep -c -- "$pat" "$p" 2>/dev/null || echo 0)"
    printf '    { "label": "%s", "path": "%s", "pattern": "%s", "count": %s }' \
        "$(esc "$label")" "$(esc "$p")" "$(esc "$pat")" "$n"
}

PATHS=(
    /opt/remedy-lab
    /opt/remedy-lab/payload.so
    /opt/remedy-lab/REMEDY-LAB.marker
    /opt/remedy-lab/keepme.conf
    /opt/remedy-lab/lab.conf
    /opt/remedy-lab/lab.json
    /opt/remedy-lab/labproc
    /usr/share/applications/remedy-lab.desktop
    /etc/xdg/autostart/remedy-lab-auto.desktop
    /usr/local/share/ca-certificates/lab-ca.crt
    /usr/local/share/ca-certificates/decoy-ca.crt
    /etc/cron.d/remedy-lab
    /etc/cron.d/innocent-cron
    /etc/systemd/system/remedy-lab.service
    /etc/systemd/system/multi-user.target.wants/remedy-lab.service
    /etc/hosts
    "$EXTROOT/remedylabremedylabremedylabremed"
    "$EXTROOT/innocentinnocentinnocentinnoce"
)

printf '{\n  "captured": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

printf '  "files": [\n'
first=1
for p in "${PATHS[@]}"; do
    [ "$first" -eq 1 ] || printf ',\n'
    first=0
    emit_file "$p"
done
printf '\n  ],\n'

printf '  "lines": [\n'
first=1
while IFS='|' read -r label p pat; do
    [ -z "$label" ] && continue
    [ "$first" -eq 1 ] || printf ',\n'
    first=0
    emit_line "$p" "$pat" "$label"
done <<'SPEC'
hosts-lab|/etc/hosts|lab.remedy.invalid
hosts-localhost|/etc/hosts|127.0.0.1	localhost
conf-implant|/opt/remedy-lab/lab.conf|remedy-lab-implant
conf-normal-first|/opt/remedy-lab/lab.conf|normal_first
conf-normal-last|/opt/remedy-lab/lab.conf|normal_last
json-implant|/opt/remedy-lab/lab.json|remedy_lab_implant
json-keep|/opt/remedy-lab/lab.json|"keep"
desktop-arg|/usr/share/applications/remedy-lab.desktop|--remedy-lab-injected-arg
desktop-exec|/usr/share/applications/remedy-lab.desktop|Exec=
cron-implant|/etc/cron.d/remedy-lab|/bin/true
cron-innocent|/etc/cron.d/innocent-cron|/bin/true
SPEC
printf '\n  ],\n'

# 도는 프로세스.
#
# **`pgrep` 을 쓰지 않는다.** 그것은 `procps` 패키지에 있고 최소 이미지에는
# 없다. 없으면 이 값이 언제나 0 이 되어 "프로세스가 죽었다" 가 **재지 않고
# 통과**한다 — 이 하네스가 다른 자리에서 경고하는 바로 그 헛통과다.
# 2026-09-03 debian:12 에서 실제로 그랬다.
#
# `/proc/<pid>/exe` 를 직접 읽는다. 그것이 이 스크립트가 하려던 일이기도 하다 —
# 독립 관찰이라면 남의 도구가 아니라 커널이 말하는 것을 봐야 한다.
n=0
for d in /proc/[0-9]*; do
    [ "$(readlink "$d/exe" 2>/dev/null)" = "/opt/remedy-lab/labproc" ] && n=$((n + 1))
done
printf '  "processes": { "labproc": %s }\n' "$n"

printf '}\n'
