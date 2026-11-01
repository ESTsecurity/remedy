# P12 P7 — 리눅스 랩 VM 준비 가이드

2026-09-23 · 이 문서는 **사람이 손으로 할 일**을 적는다. 대화형 설치와 비밀번호가
드는 일은 사람만 할 수 있다. 그 뒤의 실기 검증은 하네스가 한다.

---

## 한눈에

- **만들 것** — VMware VM 하나: Debian **12.15** (amd64, netinst 설치),
  `<VM 폴더>\Debian12x64-Test\Debian12x64-Test.vmx`, NAT(VMnet8) 망,
  스냅숏 **`remedy-lab-linux-base-v1`** (전원을 끈 채로 찍는다).
- **할 일** — 아래 1–8단계. 40–60분 걸린다(대부분 내려받기와 설치 대기).
  마지막 7·8단계의 `--check` 가 준비가 끝났는지 알려 준다.
- **그다음** — 알려 주면 `invoke-reboot-verify.sh` 로 **진짜 systemd 부팅**에서
  재검사가 돌고 흔적이 남지 않는지 잰다 (부록 A).

이미 해 둔 것:

| 무엇 | 자리 |
|---|---|
| 랩 전용 SSH 키 | WSL `~/.config/remedy-lab/linux-lab-ed25519` (지문은 `.cargo/linux_lab.yml` 의 `ssh.identity_fingerprint`) |
| 호스트 하네스 | `testbed/harness/linux/invoke-reboot-verify.sh` (WSL 에서 돈다) |
| 게스트 검사 | `testbed/harness/linux/reboot-verify.sh` · 실험 플러그인 `p7-plugin.yaml` |

### 왜 Debian 12 인가

배포 바이너리는 `rust:1.96-bookworm`(= Debian 12, glibc 2.36)에서 만들고, 리눅스
위협 증거 8개도 같은 bookworm 컨테이너에서 쟀다. VM 도 Debian 12 면 **달라지는
것이 "진짜 systemd 부팅" 하나뿐이다** — 실패하면 원인이 배포판 차이인지 부팅인지
가를 필요가 없다. 지금 안정판은 13.7 이지만 변수를 늘리지 않으려 12 로 한다.
Debian 12 는 LTS 로 **2028-06-30** 까지 보안 갱신을 받는다(공식) — 랩으로 충분하다.

---

## 1단계 — ISO 받기

| | |
|---|---|
| 파일 | `debian-12.15.0-amd64-netinst.iso` — 709,885,952 바이트(약 677 MB) |
| 주소 | https://cdimage.debian.org/cdimage/archive/12.15.0/amd64/iso-cd/debian-12.15.0-amd64-netinst.iso |
| 체크섬 파일 | https://cdimage.debian.org/cdimage/archive/12.15.0/amd64/iso-cd/SHA256SUMS |
| 기대 SHA256 | `cd4462c06aa8892e692c0c4b9c17802f38c8ab8690e85cbfb5ccaa5956e9af17` |

- 주소를 브라우저에 넣으면 가까운 미러로 넘겨 받는다(정상).
- **`debian-cd/current/` 가 아니다** — 그 폴더는 Debian 13 이다. 12 는
  `cdimage/archive/12.15.0/` 에 있다.
- 두는 곳은 VM 폴더 밖이면 어디든 된다.

받은 뒤 PowerShell 에서 확인한다 — 위 기대값과 같아야 한다:

```powershell
(Get-FileHash <ISO 폴더>\debian-12.15.0-amd64-netinst.iso -Algorithm SHA256).Hash.ToLower()
```

> 서명까지 보려면(선택): 같은 폴더의 `SHA256SUMS.sign` 과
> https://www.debian.org/CD/verify 의 안내.

---

## 2단계 — VM 만들기 (VMware Workstation 17.6.3)

`File > New Virtual Machine… > Custom (advanced)` 로 다음처럼 고른다.

| 화면 | 고를 것 |
|---|---|
| Hardware compatibility | 기본값 (Workstation 17.5 or later) |
| Install from | **Installer disc image file (iso)** → 1단계의 ISO |
| Guest operating system | **Linux** · Version **Debian 12.x 64-bit** (목록에 없으면 Debian 11.x 64-bit — 설치에는 영향이 없다) |
| Virtual machine name | **`Debian12x64-Test`** |
| Location | **`<VM 폴더>\Debian12x64-Test`** |
| Firmware | 기본값 (UEFI 든 BIOS 든 된다) |
| Processors | 1 processor · 2 cores |
| Memory | 2048 MB |
| Network | **Use network address translation (NAT)** — Windows 랩 VM 과 같은 VMnet8 |
| I/O controller · Disk type | 기본값 |
| Disk | Create a new virtual disk · **20 GB** · Store virtual disk as a single file |

**이름과 자리가 하네스에 박혀 있다**(`invoke-reboot-verify.sh` 의 `VMX`·`SNAPSHOT` 기본값). 결과로
`<VM 폴더>\Debian12x64-Test\Debian12x64-Test.vmx` 가 생겨야 한다. 다르게
만들었다면 하네스에 `--vmx '<경로>'` 를 준다.

---

## 3단계 — Debian 설치

부팅 메뉴(*installer menu (BIOS mode)*)가 뜨면 **곧바로 Enter** — 선택된 *Graphical
install* 로 들어간다(마우스로 고르고 *Continue*). **29초 안에 아무 키도 누르지 않으면
음성 안내 설치가 시작된다** — 그러면 VMware `VM > Power > Reset` 뒤 다시.

| 질문 | 답 |
|---|---|
| Language · Location · Locale | **English** · other → Asia → **Korea, Republic of** · **en_US.UTF-8** (콘솔 글자가 깨지지 않게. remedy 의 언어는 따로 정한다) |
| Keyboard | American English |
| Hostname · Domain | `remedy-lab-linux` · 빈칸 — VMware NAT 가 `localdomain` 을 채워 두면 그대로 둬도 된다 |
| Root password | **설정한다 — 비우면 안 된다.** 비우면 설치기가 root 를 잠그고 `sudo` 로 바꿔 6단계의 `su` 가 막힌다. 6단계에서 한 번 쓴다 |
| New user | 이름·계정 모두 `remedy` · 비밀번호 설정 (6단계에서 한 번 쓴다) |
| Partitioning | Guided – use entire disk → 그 디스크 → All files in one partition → Finish → **Yes** (기본 선택이 *No* 다) |
| Scan extra media | No |
| Mirror | Korea, Republic of → 맨 위 **`deb.debian.org`**(기본 · 설치기의 권장) 그대로. `ftp.kr.debian.org` 도 된다 — 2026-09-23 호스트에서 둘 다 200 · 1초 안 · Proxy 빈칸 |
| Popularity contest | No |
| **Software selection** | **Debian desktop environment · GNOME 을 끈다** · **SSH server · standard system utilities 만 켠다** |
| GRUB (BIOS 일 때만 묻는다) | Yes → 그 디스크 (`/dev/sda` 등) |

설치가 끝나면 **Continue** 로 재부팅한다. 설치 화면이 다시 뜨면 VM 설정 >
CD/DVD 의 *Connect at power on* 을 끄고 다시 켠다.

> **데스크톱을 깔지 않는 이유.** 재는 것이 부팅 때의 systemd 동작이다. 데스크톱은
> 부팅 경로에 서비스를 수십 개 더해 잰 값을 흐리고, 되돌린 뒤 갱신기가 깨어날
> 자리를 늘린다 (Windows 랩이 2026-09-11 에 그 자리에서 흔들렸다).

---

## 4단계 — 첫 로그인과 주소 확인 (VM 콘솔)

`root` 로 로그인한 뒤:

```sh
ip -4 -brief addr        # ens33 같은 줄의 VMnet8 대역 주소 — 적어 둔다
cat /proc/1/comm         # systemd
```

---

## 5단계 — 게스트 정리 (root)

**6단계를 먼저 하고 SSH 로 하는 편이 쉽다.** VMware 콘솔에는 붙여넣기가 안 된다 —
6단계가 끝나면 WSL 에서 `ssh -i $K -o UserKnownHostsFile=$KH root@$IP` 로 들어가
아래를 한 줄씩 붙여넣는다(`exit` 로 나온다). 5단계는 6단계에 기대는 것이 없다.

```sh
apt update
apt install -y open-vm-tools
systemctl is-active open-vm-tools                          # active
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer
dpkg -s unattended-upgrades >/dev/null 2>&1 && apt purge -y unattended-upgrades
```

| 무엇 | 왜 |
|---|---|
| `open-vm-tools` | 하네스가 `vmrun getGuestIPAddress` 로 주소를 묻는다. 없으면 주소를 모른다 (2026-09-23 실측: 설치기가 이미 깔아 두었다 — 그래도 같은 명령이면 된다) |
| apt 타이머 끄기 | 부팅 때 패키지 목록을 받는 일이 **부팅 시간 잰 값을 흔든다** — 이 회차가 재는 것이 그 부팅이다 |
| `unattended-upgrades` 없애기 | 되돌린 뒤 패키지가 스스로 바뀌면 회차마다 다른 기계를 재게 된다 (기본 설치에는 보통 없다) |

---

## 6단계 — SSH 키 등록 (WSL)

키는 이미 WSL 에 있다(위 표). **Windows 터미널에서 Ubuntu(WSL)를 열고** 차례로
한다. `IP=` 에는 4단계의 주소를 넣는다.

**한 줄씩 붙여넣는다.** 여러 줄을 한꺼번에 붙이면 비밀번호를 묻는 순간 뒷줄이
비밀번호 칸으로 빨려 들어가 틀린 비밀번호가 된다.

```sh
IP=192.0.2.10           # ← 4단계에서 본 주소로 바꾼다(이 값은 예시다)
K=~/.config/remedy-lab/linux-lab-ed25519
KH=~/.config/remedy-lab/linux-known_hosts

# (0) ssh-copy-id 는 임시 폴더를 ~/.ssh 안에 만든다 — WSL 에서 ssh 를 처음 쓰면
#     그 폴더가 없어 비밀번호를 묻기도 전에 멈춘다 (2026-09-23 실측, 316줄 mktemp)
mkdir -p -m 700 ~/.ssh

# (1) remedy 계정에 키를 넣는다 — 처음 접속이면 yes, 그리고 remedy 비밀번호를 묻는다
ssh-copy-id -i $K.pub -o UserKnownHostsFile=$KH remedy@$IP

# (2) 같은 키를 root 에도 넣는다 — root 비밀번호를 묻는다
ssh -t -i $K -o UserKnownHostsFile=$KH remedy@$IP \
  'su -c "install -d -m 700 /root/.ssh && cat ~remedy/.ssh/authorized_keys >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys"'

# (3) 확인 — 비밀번호를 묻지 않고 uid=0(root) 와 systemd 가 나와야 한다
ssh -i $K -o UserKnownHostsFile=$KH root@$IP 'id; cat /proc/1/comm'
```

- root 가 **키로만** 들어온다 — Debian 기본 `PermitRootLogin prohibit-password`
  그대로다. 비밀번호 로그인을 열지 않는다.
- 랩 전용 `known_hosts` 를 쓴다 — `~/.ssh` 에는 빈 폴더만 남는다(`ssh-copy-id` 의
  임시 폴더는 끝나면 지워진다).
- (선택) 처음 접속의 yes 전에 진짜 그 VM 인지 보려면 VM 콘솔에서
  `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` — 접속할 때 나오는 지문과 같아야 한다.

---

## 7단계 — 준비 점검 (WSL, VM 켠 채)

```sh
# WSL 에서 저장소 뿌리로 옮긴 뒤
testbed/harness/linux/invoke-reboot-verify.sh --check
```

**이 단계의 정상 결과**: 호스트 줄은 **스냅숏만 실패**(다음 단계에서 찍는다), 나머지
OK. 게스트 줄은 전부 OK — `SSH 키로 root 가 된다` · `systemd 가 PID 1 이다` ·
`VMware 가상 머신이다` · `open-vm-tools 가 돈다` · `apt 자동 타이머가 꺼져 있다` ·
`우리 예약이 없다`. `주의` 나 `실패` 줄은 그 줄이 가리키는 단계로 돌아간다.

---

## 8단계 — 끄고 스냅숏 찍기

1. VM 콘솔에서 `poweroff` — **완전히 꺼질 때까지** 기다린다.
2. VMware 에서 `VM > Snapshot > Take Snapshot…`
   - Name: **`remedy-lab-linux-base-v1`** (정확히 이 이름, 하나만)
   - Description: `Debian 12.15 · open-vm-tools · SSH 키 · apt 타이머 끔 · 전원 끈 상태`
3. WSL 에서 `--check` 를 다시 돌린다 — 호스트 줄이 **전부 OK**, 게스트 줄은
   `VM 이 꺼져 있다`(못잼)면 준비 끝이다.

명령으로 찍으려면(PowerShell, VM 이 꺼진 뒤):

```powershell
& "C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" -T ws snapshot `
  "<VM 폴더>\Debian12x64-Test\Debian12x64-Test.vmx" remedy-lab-linux-base-v1
```

> **왜 꺼진 채 찍는가.** 켜진 채 찍은 스냅숏은 되돌릴 때 **시계까지 그 순간으로
> 돌아간다** — Windows 랩이 2026-09-10 에 45분 넘게 시계가 어긋난 채 돌았다
> (`host/Reset-Vm.ps1` 주석). 꺼진 채 찍으면 켜질 때 시계를 호스트에서 받는다.

---

## 9단계 — 알려 주면 하네스가 잰다

```sh
testbed/harness/linux/invoke-reboot-verify.sh
```

되돌리기 → 켜기 → 배포(바이너리 · 스크립트 · 플러그인) → 치료하고 재검사 예약 →
**재부팅** → 부팅이 끝나기를 기다린다 → 확인. 결과는
`testbed/harness/results/linux-reboot-<시각>/` 에 남는다(저장소 밖). 끝나도 VM 은
켜 둔다 — 들여다볼 수 있게.

**2026-09-23 첫 실행 — 두 회차 모두 합격** (88초 · 90초, 바이너리 `d052b03f…`):

```text
재부팅 전  9/9 — 예약이 심겼고 · 자기를 지우는 줄이 있고 · 감사 로그 End 앞에 같은 명령
재부팅     25–28초 뒤 다시 올라옴 · is-system-running: running
재부팅 뒤  9/9 — 유닛 · 링크 · 임시 파일 없음 · systemd 가 부팅 3.1–3.3초에 돌려 성공 ·
           재평가 clean · 종료 0 · 회차 로그에 13줄 · 한국어 · 크래시 없음
잰 값      재평가 89–123 ms · multi-user.target 은 재평가가 끝나고 +0.3 ms 뒤
```

실제로 만든 VM: Debian 12.15 · BIOS · 커널 6.1.0-53 · systemd 252.39 · open-vm-tools 는
설치기가 깔아 두었다 · 주소는 DHCP(하네스는 매번 VMware 에 묻는다) ·
호스트 키 지문은 `.cargo/linux_lab.yml` 의 `ssh.host_key_ed25519`.

---

## 막히면

| 증상 | 할 일 |
|---|---|
| 목록에 `Debian 12.x 64-bit` 가 없다 | `Debian 11.x 64-bit` 로 만든다 — 설치에는 영향이 없다 |
| 설치 첫 화면에서 음성 안내가 나온다 | 29초 카운트다운이 끝났다 — VMware `VM > Power > Reset` 뒤 바로 Enter |
| `ssh-copy-id: ERROR: failed to create required temporary directory under ~/.ssh` | WSL 에 `~/.ssh` 가 없다 — `mkdir -p -m 700 ~/.ssh` 뒤 다시(6단계 (0)). 비밀번호 문제가 아니다 |
| 설치가 끝났는데 설치 화면이 또 뜬다 | VM 설정 > CD/DVD > *Connect at power on* 끄기 |
| `ssh-copy-id` 가 Permission denied | remedy 비밀번호 확인 · 게스트에서 `systemctl is-active ssh` |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | VM 을 새로 만든 경우다 — `rm ~/.config/remedy-lab/linux-known_hosts` 뒤 6단계부터 |
| `--check` 가 주소를 모른다 | 게스트에서 `systemctl status open-vm-tools` — 5단계 |
| `--check` 가 `PID 1 이 systemd 가 아니다` | 이미지가 틀렸다 — 1단계의 netinst 로 다시 |
| 스냅숏 이름이 둘 이상이라고 한다 | VMware 스냅숏 관리자에서 이름을 하나만 남긴다 — 하네스는 어디로 되돌릴지 모르면 멈춘다 |

## 이 VM 에 하지 않을 것

- **다른 용도로 쓰지 않는다.** 하네스가 매번 스냅숏으로 되돌린다 — 그 사이 바꾼
  것은 사라진다.
- 스냅숏을 **켜진 채** 찍지 않는다 (시계).
- 스냅숏을 고쳐 찍으면 이름을 올린다 (`…-v2`) — 하네스에 `--snapshot` 을 준다.

---

## 부록 A — 하네스가 재는 것

```text
재부팅 전 (before)
  0   systemd 가 PID 1 · 가상 머신 · 시작 전에 우리 예약이 없다
  1   예약이 심겼다 — /etc/systemd/system/remedy-verify.service + .wants 링크
  2   유닛이 실행 직전에 자기를 지운다 (ExecStartPre=-/bin/rm -f <링크> <유닛>)
  3   유닛의 명령이 감사 로그 End 바로 앞에 적혔다 · --lang ko
재부팅 뒤 (after)
  4   실제로 재부팅했다 (boot_id)
  5   유닛과 링크가 둘 다 없다 · 임시 파일도 없다          <- 자기 흔적 규칙 2
  6   systemd 가 이번 부팅에 그 유닛을 돌렸고 성공했다 (journalctl)
  7   재평가 판정이 남았다 (clean · 종료 0)
  8   재부팅 회차의 화면이 회차 로그에 남았다 · 같은 언어 · 크래시 없음
  잰 값  부팅 시간 · 재평가 시작/끝 · multi-user.target 도달
```

판정은 통과 · 실패 · 못잼 셋이다. 못 잰 것은 통과가 아니다.

재평가가 다 보지 못하면(`incomplete` · 종료 6 — 2026-10-26 부터) 6b 와 7 이 함께
실패한다(6 — 유닛이 돌았다 — 는 통과). 유닛은 0 이 아닌 종료를 실패로 적는다 —
재발(2) · 부분 치료(3)와 같다.

하네스를 VM 없이 먼저 쟀다(2026-09-23) — 가짜 systemd 컨테이너에서 모의 부팅을
하면 1·2·3·5·7·8 이 통과하고, 진짜 재부팅이 아니라 4 는 실패·6 은 못잼으로
바르게 나온다. **음성 대조**: 유닛을 돌리지 않은 기계는 5·7·8 이 실패하고, 임시
파일이 남은 기계는 5b 가 실패한다.

## 부록 B — 이 문서의 값의 출처 (2026-09-23 확인)

| 값 | 출처 |
|---|---|
| VMware Workstation 17.6.3 · VMnet8 NAT · 호스트 메모리·디스크 여유 | 호스트 실측 |
| WSL 에서 VMnet8 에 닿는다 | 실측 — WSL 에서 Windows 랩 VM 의 WinRM(5985)에 연결 |
| Debian 12.15.0 (2026-07-11) · netinst 709,885,952 바이트 | cdimage.debian.org `archive/12.15.0` · `archive/latest-oldstable` 이 같은 판을 가리킨다 |
| SHA256 `cd4462c0…af17` | 공식 `SHA256SUMS` 를 직접 받아 대조 |
| LTS 2028-06-30 | https://www.debian.org/releases/bookworm/ · https://wiki.debian.org/LTS |
| 현재 안정판 13.7.0 | cdimage.debian.org `debian-cd/current` |
