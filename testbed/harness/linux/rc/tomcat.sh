#!/bin/bash
# rc 묶음 — 실제 자바 앱 이미지(tomcat:9.0-jdk11)에서 이번 판의 log4j 룰로 컨테이너 디스크 전체를 잰다(`rc-bundle.sh`).
#
#   bash testbed/harness/linux/rc/tomcat.sh <푼 이번 판> <공식 jar 폴더> <결과 폴더>
#
# 그대로(기대 0)와, 공식 log4j-core 2.14.1 을 풀어 놓은 웹 앱에 복사한 것(기대 2 — 화면이 그 파일을 적는다). jar 는
# docker cp 로 넣는다 — 마운트를 더하면 그것이 디스크 뿌리가 된다. 아무것도 띄우지 않는다(remedy 는 읽기만 한다).
# 컨테이너에 망이 없다. 종료 코드: 0 = 둘 다 기대대로.
set -u
X=${1:?unpacked candidate}
J=${2:?jars folder}
R=${3:?result folder}
IMG=tomcat:9.0-jdk11
APP=/usr/local/tomcat/webapps/app
mkdir -p "$R"
W=$(mktemp -d /tmp/remedy-tomcat.XXXXXX)
mkdir -p "$W/app/WEB-INF/lib"
cp "$J/log4j-core-2.14.1.jar" "$W/app/WEB-INF/lib/" || { echo "$J 에 log4j-core-2.14.1.jar 가 없다"; exit 9; }
inner='n=$(find / -xdev \( -name "*.jar" -o -name "*.war" -o -name "*.ear" \) 2>/dev/null | wc -l)
t0=$(date +%s)
REMEDY_LANG=ko LANG=C.UTF-8 /p/remedy scan --plugin /p/plugins/log4j-check/plugin.yaml --out-dir /tmp/o > /tmp/s.txt 2>&1
rc=$?
echo "$CASE exit=$rc seconds=$(( $(date +%s) - t0 )) archives_on_root=$n"
cat /tmp/s.txt'
docker run --rm --pull=never --network none -v "$X:/p:ro" -e CASE=clean "$IMG" sh -c "$inner" > "$R/clean.txt" 2>&1
head -1 "$R/clean.txt"
cid=$(docker create --pull=never --network none -v "$X:/p:ro" -e CASE=vuln "$IMG" sh -c "$inner")
docker cp "$W/app" "$cid:/usr/local/tomcat/webapps/" > /dev/null
docker start -a "$cid" > "$R/vuln.txt" 2>&1
docker rm "$cid" > /dev/null
head -1 "$R/vuln.txt"
rm -rf "$W"
grep -q '^clean exit=0 ' "$R/clean.txt" && grep -q '^vuln exit=2 ' "$R/vuln.txt" && grep -qF "$APP/WEB-INF/lib/log4j-core-2.14.1.jar" "$R/vuln.txt"
