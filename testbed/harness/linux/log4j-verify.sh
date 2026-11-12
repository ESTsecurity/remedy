#!/bin/bash
# Log4j 점검 룰(log4j-check)을 리눅스 컨테이너에서 잰다.
#
# 호스트(WSL)에서, 저장소 루트:
#
#   bash testbed/harness/linux/log4j-verify.sh --bin <remedy> --plugins <log4j-check 가 든 폴더> \
#        [--jars <공식 jar 폴더>] [--out <결과 폴더>]
#
# `--bin` 은 리눅스 remedy 다 — 배포본(musl 정적)이든 개발 빌드든 ubuntu:24.04 에서 돌면 된다. `--plugins` 는
# `log4j-check/` 를 담은 폴더다(저장소의 `plugins/` 나 내려받아 푼 꾸러미의 `plugins/` — 배포 앵커를 박은 실행 파일은
# 개발용 키로 서명한 저장소 사본을 거부한다). `--jars` 는 Maven Central 의 공식 jar 를 둘 폴더다 — 없는 jar 만
# 받고(인터넷), 있는 것은 함께 받아 둔 `.sha1` 로 대조만 한다. 주지 않으면 결과 폴더 아래 `jars/`.
# 호스트에 docker · python3 · curl 과 ubuntu:24.04 이미지가 있어야 한다.
#
# # 무해한가
#
# **실검체는 없다.** 시료는 Maven Central 의 공식 배포 jar 와, 이 하네스가 그것을 war · ear · Spring Boot jar 로
# 꾸리거나 다시 묶은 것이다(`fixtures/log4j/build-cases.py`). 아무것도 실행하지 않는다 — remedy 는 파일을 읽기만
# 한다. 경우마다 네트워크 없는 일회용 컨테이너에 그 경우의 폴더 하나만 읽기 전용으로 붙인다 — 룰의 검사 범위가
# 디스크 전체(`%FIXED_DISKS%`)라 경우가 섞이지 않게. 경우 폴더는 리눅스 파일 시스템(`/tmp`)에 짓는다 — `/mnt`
# 아래는 9p 라 디스크 토큰이 걷지 않는다(붙여도 보이지 않는다).
#
# # 무엇을 재나
#
#   A  룰의 공식 해시가 Maven Central 의 그 판과 같다 — 받은 jar 를 Maven 이 게시한 SHA-1 로 대조하고, 취약 판의
#      SHA-256 은 모두 룰에 있고 고친 판은 하나도 없으며 룰에 그 밖의 해시가 없다(`fixtures/log4j/official.txt`)
#   B  공식 jar 29개를 제 이름 그대로 — 취약 판 2 · 아닌 판 0 (경계 2.3.1 · 2.3.2 · 2.12.3 · 2.12.4 · 2.17.0 ·
#      2.17.1 · logback 1.2.8 · 1.2.9)
#   C  꾸린 앱 16 — 이름 바꾼 공식 jar · war · ear · ear 안 war 안 jar · Spring Boot · 이름 바꾼 안쪽 jar · shade ·
#      JndiLookup 을 뺀 jar · 1.x 좌표가 가린 안쪽 2.x · 다시 묶은 jar · 1.3 이름은 2, 고친 판 · 로깅 없는 것은 0.
#      화면이 안쪽 경로를 `!/` 로 잇고 맞은 글자(`version=…`)를 적는다
#   D  크기 3 — 12 MiB Spring Boot 2 · jar 81개 2 · 고친 판 80개 0(깨끗한 서버는 깨끗하다)
#   E  모르는 것 3 — 잘린 jar 6(화면에 못 본 까닭) · 판이 없는 log4j-core 좌표 6 · zip 이 아닌 .jar 0
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
FX="$HERE/fixtures/log4j"
BIN=""
PLUGINS=""
JARS=""
OUT=""
IMAGE=ubuntu:24.04
MAVEN=https://repo1.maven.org/maven2
TAB=$(printf '\t')
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) BIN=$2; shift 2 ;;
        --plugins) PLUGINS=$2; shift 2 ;;
        --jars) JARS=$2; shift 2 ;;
        --out) OUT=$2; shift 2 ;;
        *) echo "모르는 인자: $1" >&2; exit 2 ;;
    esac
done

[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "--bin <remedy 실행 파일> 이 필요하다" >&2; exit 2; }
[ -f "$PLUGINS/log4j-check/plugin.yaml" ] || { echo "--plugins 에 log4j-check 가 없다: $PLUGINS" >&2; exit 2; }
for t in docker python3 curl sha1sum sha256sum; do
    command -v "$t" >/dev/null || { echo "$t 이 없다" >&2; exit 2; }
done
docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "$IMAGE 이미지가 없다 — docker pull $IMAGE" >&2; exit 2; }
[ -n "$OUT" ] || OUT="$(pwd)/testbed/harness/results/log4j-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
[ -n "$JARS" ] || JARS="$OUT/jars"
mkdir -p "$JARS"
JARS=$(cd "$JARS" && pwd)
CHECK="$PLUGINS/log4j-check/plugin.yaml"
: >"$OUT/checks.tsv"

check() { # 이름 · 1|0 · 메모
    if [ "$2" = 1 ]; then printf '  OK   %-56s %s\n' "$1" "$3"
    else printf '  실패 %-56s %s\n' "$1" "$3"; fi
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OUT/checks.tsv"
}

# ── A. 공식 jar ─────────────────────────────────────────────────────
echo "── A. 공식 jar (Maven Central) ──"
fetched=0
bad=0
: >"$OUT/official.tsv"
while read -r g a v want note; do
    case "$g" in '' | '#'*) continue ;; esac
    f="$a-$v.jar"
    if [ ! -s "$JARS/$f" ] || [ ! -s "$JARS/$f.sha1" ]; then
        u="$MAVEN/$g/$a/$v/$f"
        if curl -sSfL --retry 2 -o "$JARS/$f.part" "$u" && curl -sSfL --retry 2 -o "$JARS/$f.sha1" "$u.sha1"; then
            mv "$JARS/$f.part" "$JARS/$f"
            fetched=$((fetched + 1))
        else
            rm -f "$JARS/$f.part" "$JARS/$f.sha1"
            echo "  받지 못함: $u"
            bad=$((bad + 1))
            continue
        fi
    fi
    if [ "$(tr -d ' \r\n' <"$JARS/$f.sha1" | cut -c1-40)" != "$(sha1sum "$JARS/$f" | cut -c1-40)" ]; then
        echo "  SHA-1 이 Maven 의 것과 다르다: $f"
        bad=$((bad + 1))
    fi
    printf '%s\t%s\t%s\n' "$f" "$want" "$(sha256sum "$JARS/$f" | cut -c1-64)" >>"$OUT/official.tsv"
done <"$FX/official.txt"
n=$(wc -l <"$OUT/official.tsv")
check "A1 공식 jar 를 Maven 이 게시한 SHA-1 과 대조" "$([ "$bad" = 0 ] && [ "$n" = 29 ] && echo 1 || echo 0)" \
    "jar $n · 새로 받음 $fetched · 어긋남 $bad"
# 받지 못했으면 멈춘다 — 공식 jar 없이 합성 시료만으로 재면 해시 갈래를 재지 못한다.
[ "$bad" = 0 ] || { echo "공식 jar 를 다 갖추지 못해 멈춘다" >&2; exit 9; }

grep -oE '^[[:space:]]+- [0-9a-f]{64}' "$CHECK" | grep -oE '[0-9a-f]{64}' | sort -u >"$OUT/rule-hashes.txt"
awk -F'\t' '$2 == 2 {print $3}' "$OUT/official.tsv" | sort -u >"$OUT/vulnerable-hashes.txt"
awk -F'\t' '$2 == 0 {print $3}' "$OUT/official.tsv" | sort -u >"$OUT/other-hashes.txt"
miss=$(comm -23 "$OUT/vulnerable-hashes.txt" "$OUT/rule-hashes.txt" | wc -l)
stray=$(comm -13 "$OUT/vulnerable-hashes.txt" "$OUT/rule-hashes.txt" | wc -l)
wrong=$(comm -12 "$OUT/other-hashes.txt" "$OUT/rule-hashes.txt" | wc -l)
nr=$(wc -l <"$OUT/rule-hashes.txt")
check "A2 룰의 해시 = 받은 취약 판의 SHA-256" "$([ $((miss + stray + wrong)) = 0 ] && [ "$nr" -gt 0 ] && echo 1 || echo 0)" \
    "룰 $nr · 빠진 취약 판 $miss · 받지 않은 해시 $stray · 룰에 든 아닌 판 $wrong"

# ── 시료 ─────────────────────────────────────────────────────────────
W=$(mktemp -d /tmp/remedy-log4j-verify.XXXXXX)
cleanup() { # 컨테이너가 root 로 쓴 결과는 컨테이너로 지운다
    docker run --rm -v "$W:/w" "$IMAGE" rm -rf /w/b /w/cases /w/res >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT
mkdir -p "$W/b/plugins" "$W/res"
cp "$BIN" "$W/b/remedy"
cp -r "$PLUGINS/log4j-check" "$W/b/plugins/"
if ! python3 -I -X utf8 "$FX/build-cases.py" "$FX/official.txt" "$JARS" "$W/cases" >"$OUT/build.txt" 2>&1; then
    cat "$OUT/build.txt"
    echo "시료를 짓지 못했다" >&2
    exit 9
fi
cat "$OUT/build.txt"

# ── B ~ E. 경우마다 일회용 컨테이너 ───────────────────────────────────
: >"$OUT/cases.tsv"
t0=$(date +%s)
last=""
while IFS="$TAB" read -r grp case want note; do
    if [ "$grp" != "$last" ]; then
        echo "── $grp ──"
        last=$grp
    fi
    d="$W/res/$case"
    mkdir -p "$d"
    docker run --rm --pull=never --network none -v "$W/b:/b:ro" -v "$W/cases/$case:/scan:ro" -v "$d:/o" "$IMAGE" \
        sh -c 'REMEDY_LANG=ko LANG=C.UTF-8 /b/remedy scan --plugin /b/plugins/log4j-check/plugin.yaml \
                   --out-dir /o/out >/o/screen.txt 2>&1; echo $? >/o/rc; chmod -R a+rX /o' \
        </dev/null >/dev/null 2>&1
    rc=$(cat "$d/rc" 2>/dev/null || echo 99)
    printf '%s\t%s\t%s\t%s\t%s\n' "$grp" "$case" "$want" "$rc" "$note" >>"$OUT/cases.tsv"
    check "$case" "$([ "$rc" = "$want" ] && echo 1 || echo 0)" "기대 $want · 종료 $rc · $note"
    mkdir -p "$OUT/cases/$case"
    cp "$d/screen.txt" "$d/rc" "$OUT/cases/$case/" 2>/dev/null
    find "$d/out" -name scan.json -exec cp {} "$OUT/cases/$case/" \; 2>/dev/null
done <"$W/cases/expect.tsv"
echo "경우 $(wc -l <"$OUT/cases.tsv") · $(($(date +%s) - t0))초"

echo "── 화면 ──"
screen_has() { grep -qF "$2" "$OUT/cases/$1/screen.txt" 2>/dev/null && echo 1 || echo 0; }
check "S1 안쪽 경로를 !/ 로 잇는다 (c05)" \
    "$(screen_has c05-ear-war-jar 'app.ear!/web/app.war!/WEB-INF/lib/log4j-core-2.14.1.jar')" "ear → war → jar"
check "S2 맞은 글자를 적는다 (c14)" "$(screen_has c14-rebuilt '(내용 version=2.14.1)')" "pom.properties 의 version"
check "S3 못 본 까닭을 적는다 (e01)" "$(screen_has e01-truncated '못 본 까닭 broken')" "잘린 jar"

# 칸 수까지 본다 — 시료를 짓다 멈추면 남은 경우가 조용히 사라지고 "실패 0" 이 남는다.
EXPECTED=56 # A 2 · B 29 · C 16 · D 3 · E 3 · 화면 3
pass=$(awk -F'\t' '$2 == 1' "$OUT/checks.tsv" | wc -l)
fail=$(awk -F'\t' '$2 != 1' "$OUT/checks.tsv" | wc -l)
echo
echo "통과 $pass · 실패 $fail  (전체 $((pass + fail)) / 기대 $EXPECTED)" | tee "$OUT/verdict.txt"
[ "$fail" = 0 ] && [ "$((pass + fail))" = "$EXPECTED" ]
