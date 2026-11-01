# 랩 값은 `.cargo/*.yml` 에서 읽는다 — 리눅스 하네스의 공용 함수.
#
# **스크립트에 박지 않는다.** VMX 경로와 호스트의 `vmrun` 자리는 기계마다
# 다르고, 박아 두면 기계가 바뀔 때 여러 곳이 함께 어긋난다. 운영 값은 커밋하지
# 않는 `.cargo/*.yml` 에 두고(견본 `.cargo/*.example.yml`) 여기서 읽는다.
# Windows 쪽 짝은 `host/VmSession.ps1` 의 `Get-LabConfigValue` 다.
#
# **YAML 전부를 읽지 않는다.** 이 파일들의 모양 — 들여쓴 `키: 값` — 만 읽는다.
# 목록·여러 줄 값은 다루지 않으므로 그런 칸을 물으면 빈 값이 돌아온다.
#
# 쓰는 법:
#   . "$HERE/lab-config.sh"
#   VMX="$(lab_value linux_lab linux_lab.identity.vmx)"
#   VMX="$(lab_need "$VMX" --vmx linux_lab linux_lab.identity.vmx)"

# lab_value <파일 이름(확장자 없이)> <점으로 이은 칸 이름>
# 값을 찾으면 적어 내고, 없으면 아무것도 적지 않는다(종료 0).
lab_value() {
    local file="$1" key="$2"
    local path="${REPO:-.}/.cargo/${file}.yml"
    [ -f "$path" ] || return 0
    awk -v want="$key" -v sq="'" -v dq='"' '
    {
        line = $0
        if (line ~ /^[[:space:]]*#/) next
        if (line ~ /^[[:space:]]*$/) next
        ci = index(line, ":")
        if (ci == 0) next
        name = substr(line, 1, ci - 1)
        val = substr(line, ci + 1)
        # 들여쓴 칸 수를 센다. 깊이가 아니라 칸 수로 쌓아 들여쓰기 폭을
        # 가정하지 않는다.
        ind = match(name, /[^[:space:]]/) - 1
        if (ind < 0) next
        name = substr(name, ind + 1)
        if (name !~ /^[A-Za-z0-9_.-]+$/) next
        while (top > 0 && indents[top] >= ind) top--
        top++
        indents[top] = ind
        names[top] = name
        full = names[1]
        for (i = 2; i <= top; i++) full = full "." names[i]
        if (full != want) next
        gsub(/^[[:space:]]+/, "", val)
        gsub(/[[:space:]]+$/, "", val)
        # 값 자리가 주석뿐이면 값이 없는 것이다.
        if (substr(val, 1, 1) == "#") exit
        # 따옴표로 감쌌으면 닫는 따옴표까지가 값이다 — 꼬리 주석을 먼저 떼면
        # 값 안의 `#` 를 주석으로 잘못 읽는다.
        q = substr(val, 1, 1)
        if (q == sq || q == dq) {
            rest = substr(val, 2)
            p = index(rest, q)
            if (p > 0) print substr(rest, 1, p - 1)
            exit
        }
        sub(/[[:space:]]+#.*$/, "", val)
        print val
        exit
    }
    ' "$path"
}

# lab_need <지금 값> <플래그 이름> <파일> <칸>
# 값이 있으면 그대로, 없으면 `.cargo/*.yml` 에서 읽고, 그래도 없으면 멈춘다.
# **조용히 기본값으로 돌지 않는다** — 엉뚱한 기계를 되돌리는 것보다 멈추는
# 편이 낫다.
lab_need() {
    local given="$1" flag="$2" file="$3" key="$4"
    if [ -n "$given" ]; then
        printf '%s' "$given"
        return 0
    fi
    local found
    found="$(lab_value "$file" "$key")"
    if [ -n "$found" ]; then
        printf '%s' "$found"
        return 0
    fi
    echo "실패 $flag 값을 알 수 없다. $flag 로 주거나 .cargo/${file}.yml 의" \
         "'$key' 에 적을 것 (견본: .cargo/${file}.example.yml)" >&2
    return 1
}
