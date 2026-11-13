#!/bin/bash
# `ab-sudo.sh` 의 안쪽 — debian:12(root) 안에서 꾸러미 a · b 로 동반 프로그램 띄우기의 실제 sudo 경우들.
#   /pkgs/a /pkgs/b  푼 꾸러미(읽기 전용)   /out  결과(쓰기)
# 경우마다 새 사본에서 돈다. 경우마다 종료 코드 · 화면 · out/ 의 소유자/권한 트리를 남긴다.
set -u
apt-get -qq update > /out/apt.log 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y sudo netcat-openbsd >> /out/apt.log 2>&1 \
    || { echo "apt failed"; exit 7; }
useradd -m -u 4242 -s /bin/bash alice
echo 'alice ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/alice
chmod 440 /etc/sudoers.d/alice
chmod 755 /home/alice
NET_RULE=plugins/php2shell-url-check/plugin.yaml
MENU_IN='1\ny\nhttp://127.0.0.1:9/\n\n\n0\n'

fresh() { # <판> <대상 폴더> <소유자>
    rm -rf "$2"
    cp -a "/pkgs/$1" "$2"
    chown -R "$3:$3" "$2"
}
tree_of() { # <폴더> <파일>
    (cd "$1" && find out -printf '%u %m %P\n' 2>/dev/null | sort) > "$2"
    chmod 644 "$2"
}
as_alice() { su alice -c "$1"; }

for v in a b; do
    o=/out/$v
    mkdir -p "$o"
    chmod 777 "$o"
    # 원격 항목의 메뉴 번호 — 첫 화면에서 읽는다(룰이 늘면 밀린다)
    fresh "$v" /root/m0 root
    (cd /root/m0 && printf '0\n' | LANG=ko_KR.UTF-8 timeout 60 script -q -e -c "./remedy > $o/menu0.txt 2>&1" /dev/null)
    r=$(grep -m1 -E '^ +[0-9]+\. .*\[네트워크 사용\]' "$o/menu0.txt" | sed -E 's/^ +([0-9]+)\..*/\1/')
    echo "net_item $r" > "$o/codes.txt"
    input="$r\\n$MENU_IN"

    # c1 사용자 홈에서 sudo: 동반 프로그램은 그 사용자로 돈다
    fresh "$v" /home/alice/c1 alice
    as_alice "cd ~/c1 && { printf '$input'; sleep 8; } | LANG=ko_KR.UTF-8 timeout 120 script -q -e -c 'sudo ./remedy > $o/c1.txt 2>&1' /dev/null"
    echo "c1-sudo-drop $?" >> "$o/codes.txt"
    tree_of /home/alice/c1 "$o/c1.tree"

    # c2 umask 077: 사용자가 out/ 을 지나지 못한다 — 그렇다고 말하고 root 로 돈다
    fresh "$v" /home/alice/c2 alice
    as_alice "cd ~/c2 && umask 077 && { printf '$input'; sleep 8; } | LANG=ko_KR.UTF-8 timeout 120 script -q -e -c 'sudo ./remedy > $o/c2.txt 2>&1' /dev/null"
    echo "c2-sudo-umask077 $?" >> "$o/codes.txt"
    tree_of /home/alice/c2 "$o/c2.tree"

    # c3 root 홈의 꾸러미: 사용자가 닿지 못한다 — 그렇다고 말하고 root 로 돈다
    fresh "$v" /root/c3 root
    as_alice "cd ~ && { printf '$input'; sleep 8; } | LANG=ko_KR.UTF-8 timeout 120 script -q -e -c 'sudo bash -c \"cd /root/c3 && ./remedy\" > $o/c3.txt 2>&1' /dev/null"
    echo "c3-sudo-root-home $?" >> "$o/codes.txt"
    tree_of /root/c3 "$o/c3.tree"

    # c4 sudo 없이 root: 내려갈 사용자가 없다
    fresh "$v" /root/c4 root
    (cd /root/c4 && { printf "$input"; sleep 8; } | LANG=ko_KR.UTF-8 timeout 120 script -q -e -c "./remedy > $o/c4.txt 2>&1" /dev/null)
    echo "c4-root-direct $?" >> "$o/codes.txt"
    tree_of /root/c4 "$o/c4.tree"

    # c5 sudo 아래 명령줄
    fresh "$v" /home/alice/c5 alice
    as_alice "cd ~/c5 && sudo ./remedy scan --plugin $NET_RULE --out-dir out --url http://127.0.0.1:9/ --consent y > $o/c5.txt 2>&1 < /dev/null"
    echo "c5-sudo-cli $?" >> "$o/codes.txt"
    tree_of /home/alice/c5 "$o/c5.tree"

    # c6 원격 룰만 든 폴더 · 터미널 없음 · 권한 없음: 실행법을 말한다(4)
    fresh "$v" /home/alice/c6 alice
    find /home/alice/c6/plugins -mindepth 1 -maxdepth 1 -type d ! -name php2shell-url-check -exec rm -rf {} +
    as_alice "cd ~/c6 && LANG=ko_KR.UTF-8 ./remedy < /dev/null > $o/c6.txt 2>&1"
    echo "c6-only-net-noterm $?" >> "$o/codes.txt"

    # c7 동반 프로그램 폴더를 지웠다: 띄우지 않는다(5)
    fresh "$v" /home/alice/c7 alice
    rm -rf /home/alice/c7/remedy-net
    as_alice "cd ~/c7 && sudo ./remedy scan --plugin $NET_RULE --out-dir out --url http://127.0.0.1:9/ --consent y > $o/c7.txt 2>&1 < /dev/null"
    echo "c7-companion-absent $?" >> "$o/codes.txt"
    tree_of /home/alice/c7 "$o/c7.tree"

    # c8 답하지 않는 서버를 기다리는 동안 Ctrl+C: 본체 6 · 결과에 interrupted
    fresh "$v" /home/alice/c8 alice
    nc -l 127.0.0.1 8099 > /dev/null 2>&1 &
    ncpid=$!
    sleep 1
    as_alice "cd ~/c8 && { sleep 3; printf '\\003'; sleep 6; } | LANG=ko_KR.UTF-8 timeout 60 script -q -e -c 'sudo ./remedy scan --plugin $NET_RULE --out-dir out --url http://127.0.0.1:8099/ --consent y > $o/c8.txt 2>&1' /dev/null"
    echo "c8-ctrl-c $?" >> "$o/codes.txt"
    kill "$ncpid" 2> /dev/null
    tree_of /home/alice/c8 "$o/c8.tree"
    grep -rhoE '"interrupted": *(true|false)' /home/alice/c8/out > "$o/c8.interrupted" 2> /dev/null
    chmod 644 "$o"/* 2> /dev/null
done
