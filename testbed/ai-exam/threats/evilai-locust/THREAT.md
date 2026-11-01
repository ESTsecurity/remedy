<!-- schema_version: 1 | min_core: 1.0.0 | generated: false -->

# 지정 위협 설명

**출제자 주의 — 두 가지.**

1. 아래 본문에 매니페스트 필드명·연산자 이름이 **한 개도 없다.** 규격 표현이
   섞이면 시험이 아니라 받아쓰기가 된다.
2. **본문은 `corpus/infected/` 의 스냅샷에서 실측해 쓴다.** 상상해서 쓰면
   시험 문제와 채점 데이터가 어긋나고, 응시자는 도달할 수 없는 답을 요구받는다.
   1 회차가 실제로 그렇게 무너졌다 — `runs/2026-08-26-opus-5/NOTES.md`.

같이 주는 것: [`rules/evilai.yar`](rules/evilai.yar) — 분석가가
검체 16건에서 도출한 YARA 룰이다. **왜 주는가**는 아래 *"페이로드"* 절에 있다.

---

## 관측 보고 — EvilAI (Locust)

감염된 Windows 10 사용자 PC 를 확보해 다음을 관측했다. 값은 그 PC 에서 실제로
읽은 것이다.

### 지속성

Windows 작업 스케줄러에 작업이 하나 등록되어 있다. 등록 위치가 OS 자신의 작업
트리 안이다 — 정상 Windows 작업들이 모여 있는 `\Microsoft\Windows\` 아래에
자리를 잡아, 작업 목록을 눈으로 훑을 때 묻힌다.

작업이 실행하는 것은 **그 PC 에 이미 설치돼 있던 정상 Node.js 런타임**이다.

```
실행 파일   C:\Program Files\nodejs\node.exe
인자        "C:\Users\test\AppData\Local\Programs\SystemSoftwareUpdaterV2-q5ty\preload.js"
```

**검체는 런타임을 갖고 오지 않는다. 이미 있는 것을 빌려 쓴다.** 실행 파일에는
유효한 코드 서명이 붙어 있고 손대지 않았다. 악성 코드는 인자로 넘기는 `.js`
쪽에 있다.

폴더 이름(`SystemSoftwareUpdaterV2-q5ty`)과 스크립트 이름(`preload.js`)은
**감염마다 바뀐다.** 꼬리 `-q5ty` 는 매번 다르다. 고정된 것은 자리 —
사용자 프로필의 `AppData\Local\Programs` 아래 — 뿐이다.

### 페이로드

그 폴더 안에 `.js` 파일이 있다. 관측한 검체에서는 254 바이트짜리 하나였다.
폴더 자체가 검체가 만든 것이고, 감염 전부터 있던 사용자 파일이 섞여 있는
경우는 관측되지 않았다.

본문은 문자열 배열 난독화이고 — **읽을 수 있는 흔적이 하나도 없다.**

- URL·도메인·IP: 0 건
- 경로 문자열: 0 건
- `require` · `child_process` · `Buffer.from` 같은 API 이름: 0 건

전부 커스텀 알파벳으로 인코딩된 짧은 상수로 바뀌어 있다. 풀면 AES 복호 + zlib
해제 로더가 나온다.

> **그래서 YARA 룰을 함께 준다.** 이 검체는 사람이 읽어서 뽑을 문자열이 없다.
> 분석가가 검체 16건을 교차 분석해 인코딩 상수를 군집화하고 임계값을 계산했다.
> 그 도출은 검체를 손에 쥐어야 되는 일이므로 룰 작성자가 다시 할 수 없다 —
> `threat-rules/evilai.yar` 를 **그대로** 쓴다.
>
> 그 파일 머리에 분석가가 남긴 경고가 있다. **읽고 따를 것.**

### 자동 실행

예약 작업과 별개로, 사용자 자동 실행 항목에도 같은 스크립트를 가리키는 줄이
하나 더 있다.

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SystemSoftwareUpdater
  "C:\Program Files\nodejs\node.exe" "C:\Users\test\AppData\Local\Programs\SystemSoftwareUpdaterV2-q5ty\preload.js"
```

둘 중 하나만 지우면 나머지가 다시 살린다.

### 방어 회피

Microsoft Defender 의 검사 제외 목록에 그 폴더가 경로 예외로 등록되어 있다.
검체가 스스로 넣은 것이다 — 감염 전 스냅샷에는 없었다.

```
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
  C:\Users\test\AppData\Local\Programs\SystemSoftwareUpdaterV2-q5ty
```

### 실행 중 상태

감염된 PC 를 켜 둔 상태에서는 그 스크립트를 인자로 받은 `node.exe` 프로세스가
떠 있다. 파일을 먼저 지우려 하면 사용 중이라 실패한다.

**확보한 스냅샷에는 그 프로세스가 없다** — 수집 시점에 작업 트리거가 아직 돌지
않았다. 감염 PC 마다 다르므로 **있을 때도 없을 때도 처리돼야 한다.**

### 오탐 위험 — 반드시 읽을 것

이 검체가 빌려 쓰는 `node.exe` 는 **정상 개발자 PC 에 흔히 있다.** 사내 개발
PC 를 조사했을 때 다음이 나왔다.

- `AppData\Local\Programs` 아래에 설치된 정상 도구들(에디터·런타임)이 자기
  `node.exe` 를 갖고 있다
- 그중 일부는 예약 작업으로 업데이트 검사를 돌린다 — 명령이 `node.exe` 이고
  인자가 `.js` 인 **정상 작업이 실재한다**
- 서명 주체로 가르려는 시도는 **통하지 않는다.** 검체가 쓰는 `node.exe` 와
  개발자 PC 의 `node.exe` 는 같은 파일이다

### 요구

이 검체를 탐지하고, 지속성·페이로드·자동 실행 항목을 제거하고, Defender 제외
설정을 원래대로 되돌려야 한다. 실행 중인 프로세스도 다뤄야 한다.
