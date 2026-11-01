#!/bin/bash
# 수집 상한에 걸려 잘렸을 때 종료 코드 6 이 나오는가 — **컨테이너 안에서** 돈다.
#
# # 왜 이것만 못 재고 있었나
#
# 관측 불완전(6)의 사유는 넷이었다 — 잘림 · 접근 거부 · 미수집 subject · 선언한
# 자리가 전부 없음(다섯째 YARA 미평가는 2026-10-26 에 더해졌다 · Invoke-ObsVerify.ps1).
# 앞의 셋은 2026-09-11~12 에 재어졌는데 **잘림만 남았다.**
#
# 까닭은 상한이 크고 손잡이가 없다는 것이다. `Scope::max_files` 는
# **500,000 하드코딩**이고(`scope.rs` · `pipeline.rs` 두 자리) 매니페스트로도
# `--config` 로도 바꿀 수 없다. 그래서 재려면 **진짜로 넘기는 수밖에 없다.**
#
# 감당할 만하다. 콘솔 캡처의 A5 절이 이미 20만 개를 2초에 처리한다 — 20바이트
# 짜리 파일은 읽기도 해시도 싸다.
#
# # 왜 리눅스인가
#
# 파일 50만 개를 만들고 지우는 일이라 **컨테이너가 맞는 자리**다. 끝나면
# 컨테이너와 함께 사라지고, 랩 VM 의 디스크를 50만 inode 로 채우지 않는다.
#
# # 음성 대조가 있어야 뜻이 있다
#
# 상한 아래의 회차가 **0** 을 내는 것을 함께 재지 않으면, 6 이 나왔다는 사실
# 만으로는 "이 룰은 늘 6 을 낸다" 와 구별되지 않는다.
#
# # 쓰는 법 (저장소 루트에서)
#
#     docker run --rm \
#         -v "$PWD:/repo" \
#         -v <Windows 쪽 .cargo 의 WSL 경로>/registry:/usr/local/cargo/registry \
#         -v remedy-bookworm-target:/tmp/remedy-bookworm \
#         -e CARGO_TARGET_DIR=/tmp/remedy-bookworm \
#         rust:1.96-bookworm bash /repo/testbed/harness/linux/trunc-verify.sh

set -u

REL=${CARGO_TARGET_DIR:-/repo/target}/release/remedy
W=/tmp/trunc-verify
CAP=500000 # Scope::max_files — 코드에 박힌 값이다

pass=0
total=0
judge() { # judge <이름> <조건이 참인가(0/1)> <상세>
    total=$((total + 1))
    if [ "$2" = "0" ]; then
        pass=$((pass + 1))
        printf '  OK   %-34s %s\n' "$1" "$3"
    else
        printf '  실패 %-34s %s\n' "$1" "$3"
    fi
}

rule() { # rule <id> <루트>
    cat <<YAML
schema_version: 1
id: $1
version: 1.0.0
min_core: '1.0.0'
platforms: [linux]
name:
  ko: '수집 상한 시험'
  en: 'collection cap probe'
scan_roots:
  - '$2'
subjects: [file]
detect:
  - id: junk
    subject: file
    where:
      # 아무것도 맞히지 않는다. 재는 것은 **관측이 완전한가**뿐이다.
      - { field: path, op: ends_with, value: '.never-matches-anything' }
verdict:
  require: 'junk'
YAML
}

echo "########## 준비"
if [ ! -x "$REL" ]; then
    echo "배포 바이너리가 없다: $REL"
    exit 2
fi
rm -rf "$W"
mkdir -p "$W/over" "$W/under" "$W/out" "$W/state"

# 상한을 **하나 넘긴다.** 20바이트짜리를 `split` 로 찍어 낸다 — 파일마다
# `dd` 를 부르는 것보다 훨씬 빠르다.
echo "파일 $((CAP + 1))개 만드는 중..."
head -c $(((CAP + 1) * 20)) /dev/zero | split -b 20 -a 7 - "$W/over/f"
over_n=$(find "$W/over" -type f | wc -l)
echo "  만든 것: $over_n 개 (상한 $CAP)"

# 음성 대조 — 상한 한참 아래.
head -c 2000 /dev/zero | split -b 20 -a 4 - "$W/under/g"
under_n=$(find "$W/under" -type f | wc -l)
echo "  대조군: $under_n 개"

rule trunc-over "$W/over" >"$W/over.yaml"
rule trunc-under "$W/under" >"$W/under.yaml"

echo
echo "########## ① 상한을 넘긴다"
LANG=C.UTF-8 REMEDY_LANG=ko "$REL" scan --plugin "$W/over.yaml" \
    --out-dir "$W/out/over" --state-dir "$W/state" 2>&1 | tee "$W/over.txt"
over_rc=${PIPESTATUS[0]}
echo "[exit=$over_rc]"

echo
echo "########## ② 상한 아래 (음성 대조)"
LANG=C.UTF-8 REMEDY_LANG=ko "$REL" scan --plugin "$W/under.yaml" \
    --out-dir "$W/out/under" --state-dir "$W/state" 2>&1 | tee "$W/under.txt"
under_rc=${PIPESTATUS[0]}
echo "[exit=$under_rc]"

echo
echo "########## 판정"
[ "$over_n" -gt "$CAP" ]
judge "상한을 넘기는 더미를 만들었다" $? "$over_n > $CAP"

[ "$over_rc" = "6" ]
judge "잘리면 6 이다" $? "exit=$over_rc"

# 문구는 2026-09-30 화면 마감(합쇼체) 뒤의 것이다 — '잘렸다' 를 찾던 동안 6/7 이었다
# (2026-10-26 에 맞췄다).
grep -q "수집이 상한에 걸려 잘렸습니다" "$W/over.txt"
judge "사유를 '잘렸습니다' 로 말한다" $? "관측 불완전"

grep -q "'위협 없음' 을 말할 수 없습니다" "$W/over.txt"
judge "'위협 없음' 을 말하지 않는다" $? "0 과 나뉜다"

# **잘려도 본 것은 보고한다.** 잘림은 "아무것도 못 봤다" 가 아니다.
n=$(grep -o '흔적 [0-9]*건' "$W/over.txt" | head -1)
[ -n "$n" ]
judge "그래도 본 것은 보고한다" $? "${n:-없음}"

[ "$under_rc" = "0" ]
judge "상한 아래면 0 이다" $? "exit=$under_rc"

grep -q "위협이 발견되지 않았습니다" "$W/under.txt"
judge "그때는 '위협 없음' 이 선다" $? "완전한 관측"

echo
echo "판정 $pass/$total"
rm -rf "$W"
[ "$pass" = "$total" ]
