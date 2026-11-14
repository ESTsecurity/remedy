#!/bin/bash
# G9(룰의 검체 오탐)의 정상 파일 코퍼스 — 이미지마다 `/etc` · `/usr` · `/opt` 를 Windows 에서 보이는 폴더에 꺼낸다.
#
# 호스트(WSL)에서:
#
#   bash testbed/harness/linux/g9-corpus.sh <꺼낼 폴더(WSL 경로 — /mnt/... 면 Windows 에서 보인다)> <이미지> [<이미지> ...]
#
# 이미지는 **정상 설치**여야 한다 — 그 룰이 보는 배포판에 그 소프트웨어를 배포판 저장소에서 깐 것. 하네스가 지어 둔
# 이미지(`remedy-harness/apache:*` · `remedy-harness/openssh:*`)가 그 꼴이다. 실행하지 않는다 — `docker create` 한 컨테이너를
# `docker export` 해 그 셋만 푼다. 그 다음은 Windows 에서:
#
#   cargo xtask yara --rules plugins/<룰>/rules --rule <YARA 규칙 이름> --scan <꺼낸 폴더> --expect clean
#
# **리눅스 링크는 Windows 가 열지 못해 `못 훑음` 으로 세어진다** — 이미지마다 링크 수를 적으니 `못 훑음` 과 대조한다
# (docs/긴급-대응.md ④). 대상 파일 시스템이 담지 못하는 특수 파일은 tar 가 건너뛰고 그 수를 적는다.
#
# 종료 코드: 0 = 이미지 전부를 꺼냈다 · 1 = 하나라도 못 꺼냈다 · 2 = 인자가 모자라다.
set -u
[ $# -ge 2 ] || { echo "꺼낼 폴더와 이미지 하나 이상이 필요하다" >&2; exit 2; }
DEST=$1
shift
command -v docker >/dev/null || { echo "docker 가 없다" >&2; exit 2; }
mkdir -p "$DEST"
bad=0
for img in "$@"; do
    t=$(echo "$img" | sed 's#^.*/##; s#:#-#g')
    if [ -e "$DEST/$t" ]; then echo "$t: 이미 있다 — 빈 자리에 꺼낸다"; bad=1; continue; fi
    docker image inspect "$img" >/dev/null 2>&1 || { echo "$t: 이미지가 없다 — $img"; bad=1; continue; }
    mkdir -p "$DEST/$t"
    cid=$(docker create "$img" 2>/dev/null) || { echo "$t: 컨테이너를 만들지 못했다"; bad=1; continue; }
    t0=$(date +%s)
    # 메시지를 영어로 고정한다 — 이미지에 없는 `/opt` 의 알림(Not found in archive)과 그 뒤의 끝맺음 줄은 건너뛴 파일이
    # 아니므로 세지 않는다(번역되면 거르지 못한다).
    docker export "$cid" | LC_ALL=C tar -x -C "$DEST/$t" --no-same-owner --no-same-permissions --wildcards 'etc/*' 'usr/*' \
        'opt/*' 2>"$DEST/$t.tar-errors.txt"
    docker rm "$cid" >/dev/null 2>&1
    files=$(find "$DEST/$t" -type f 2>/dev/null | wc -l)
    links=$(find "$DEST/$t" -type l 2>/dev/null | wc -l)
    errs=$(grep -v -E 'Not found in archive|Exiting with failure status due to previous errors' "$DEST/$t.tar-errors.txt" \
        2>/dev/null | grep -c .)
    echo "$t 파일 $files · 링크 $links · tar 가 건너뛴 것 $errs · $(( $(date +%s) - t0 ))초"
done
exit "$bad"
