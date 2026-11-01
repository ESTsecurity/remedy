/*
   evilai.yar — EvilAI (Locust) 계열 JavaScript 페이로드
   VT 패밀리명: meadowlocust

   이 파일의 문자열은 **지어낸 것이 아니다.** VirusTotal 에서 확보한 검체
   16건(JavaScript)에서 뽑아 교차 확인했다. 설계-04 §2 가 "그럴듯한 문자열을
   지어 넣으면 그것이 곧 오탐 사고의 씨앗" 이라 비워 둔 자리를 채운 것이다.

   ── 검체가 어떻게 생겼나 ────────────────────────────────────────────────
   전부 obfuscator.io 계열 문자열배열 난독화이고, 평문 IOC 가 하나도 없다
   (URL·도메인·경로·"preload" 전부 0건). 그래서 룰은 인코딩된 상수와 골격을
   겨눈다.

   문자열 배열은 커스텀 알파벳 base64 로 인코딩돼 있다. 표준과 달리 소문자가
   앞에 온다:
       abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=
   키가 없으므로 같은 평문은 언제나 같은 상수가 된다. 풀어 보면 3글자 조각들
   이고, 이어 붙이면 require / process / createDecipheriv / aes / hex / zlib /
   readFileSync 가 나온다 — AES 복호 + zlib 해제 로더다.

   ── 왜 임계값이 이 숫자인가 ─────────────────────────────────────────────
   군집마다 "군집 안 검체가 가진 최소 개수" 와 "군집 밖 검체가 가진 최대
   개수" 를 재고, 그 사이에 임계값을 두었다. 밖 최대보다 크지 않으면 다른
   군집이 걸리고, 안 최소보다 크면 자기 군집을 놓친다.

   ── 실측 (cargo xtask yara, 제품 엔진) ─────────────────────────────────
   탐지   meadowlocust 검체              16 / 16
   오탐   호스트 청정 .js            0 / 25,863   (VS Code · Node 런타임 · node_modules 3벌)
   오탐   VM 청정 .js                 0 /  3,750   (remedy-lab-base-v2, Defender 실시간보호 켠 상태)
   오탐   타 패밀리 검체 25종          0 /    625
   셋 다 "못 훑음 0건" 이다. 훑지 못한 파일이 있으면 그만큼은 못 본 것이므로
   xtask 가 애초에 통과시키지 않는다.

   남는 위험을 솔직히 적어 둔다: rc4 룰은 악성코드가 아니라 **난독화기**의
   골격을 겨눈다. 같은 도구·같은 설정으로 난독화한 정상 소프트웨어는 원리상
   걸릴 수 있다. 위 코퍼스에서 0건이었을 뿐 "세상에 없다" 는 뜻이 아니다.
   플러그인이 이 룰을 악성 예약작업이 가리키는 디렉터리(${malicious-task.
   script_dir}) 안에서만 돌리는 것이 그 위험을 실질적으로 막는다. 이 룰을
   시스템 전역 스캔에 그대로 쓰면 안 된다.

   ── 엔진 제약 (실측) ───────────────────────────────────────────────────
   같은 문자열 리터럴이 한 파일의 **두 룰에 중복되면** yara-x 가 컴파일 중
   스택을 넘긴다. 군집1 과 군집2 는 원래 상수 12개를 공유했고 그대로 두면
   죽었다. 그래서 아래 두 룰의 문자열 집합은 **서로소**로 유지한다. 컴파일이
   안 되면 룰이 틀린 게 아니라 전부 미평가가 되고, 그 상태의 "오탐 0건" 은
   측정이 아니라 거짓이다.

   ── 갱신하는 법 ────────────────────────────────────────────────────────
   상수를 손으로 넣거나 고치지 말 것. 오타 난 상수는 오류가 아니라 조용히
   안 맞을 뿐이라, 룰이 반쯤 죽은 채로 시험을 통과한다.

   새 검체가 생기면 검체에서 다시 **도출**해야 한다. 도출 절차(군집화 기준,
   임계값 계산, 서로소 조건)는
       claudedocs/P9-EvilAI-YARA-룰-도출과-실측.md
   에 적혀 있다. 고친 뒤에는 반드시 아래 셋을 다시 돌릴 것 — 임계값은 검체
   구성이 바뀌면 같이 바뀐다.
       cargo xtask yara --rules <이 디렉터리> --expect match --scan <검체>
       cargo xtask yara --rules <이 디렉터리> --expect clean --scan <청정 .js>
*/

/* 군집1 — 소형 로더 8건 (00f28bcb94, 43421aced1, 9cc6850cdc, a14541acaf, ac8f56e9dd, b8be9a5e0a, d4527b9f2a, d9d24f83d5)
   공유 상수 90개. 군집 안 최소 90 · 군집 밖 최대 13. */
private rule evilai_locust_strarray_loader
{
    meta:
        family    = "meadowlocust"
        samples   = 8
        shared    = 90
        threshold = 20
    strings:
        $a00 = "'AM9P'" ascii
        $a01 = "'AMvJ'" ascii
        $a02 = "'AgfZ'" ascii
        $a03 = "'Agv4'" ascii
        $a04 = "'AgvK'" ascii
        $a05 = "'AgvY'" ascii
        $a06 = "'Aw5L'" ascii
        $a07 = "'Aw5N'" ascii
        $a08 = "'Axb0'" ascii
        $a09 = "'AxbO'" ascii
        $a10 = "'Axzm'" ascii
        $a11 = "'B21W'" ascii
        $a12 = "'B2jQ'" ascii
        $a13 = "'BNqZ'" ascii
        $a14 = "'Bgvt'" ascii
        $a15 = "'Bw9K'" ascii
        $a16 = "'BwfW'" ascii
        $a17 = "'BwvY'" ascii
        $a18 = "'BxbP'" ascii
        $a19 = "'C01V'" ascii
        $a20 = "'C1n5'" ascii
        $a21 = "'C2LV'" ascii
        $a22 = "'C2v0'" ascii
        $a23 = "'C3vI'" ascii
        $a24 = "'CM9T'" ascii
        $a25 = "'CMLW'" ascii
        $a26 = "'CMvH'" ascii
        $a27 = "'CMvW'" ascii
        $a28 = "'CMvZ'" ascii
        $a29 = "'CgvY'" ascii
        $a30 = "'ChjV'" ascii
        $a31 = "'ChrV'" ascii
        $a32 = "'DMfS'" ascii
        $a33 = "'Dg90'" ascii
        $a34 = "'Dg9Y'" ascii
        $a35 = "'DgXP'" ascii
        $a36 = "'DgvK'" ascii
        $a37 = "'DgvU'" ascii
        $a38 = "'DhLe'" ascii
        $a39 = "'DhLo'" ascii
        $a40 = "'DwXL'" ascii
        $a41 = "'DxbK'" ascii
        $a42 = "'EMXP'" ascii
        $a43 = "'Ew5J'" ascii
        $a44 = "'ExbL'" ascii
        $a45 = "'lMPZ'" ascii
        $a46 = "'mKXf'" ascii
        $a47 = "'q2LW'" ascii
        $a48 = "'rMXH'" ascii
        $a49 = "'rgf0'" ascii
        $a50 = "'rgvJ'" ascii
        $a51 = "'sw5M'" ascii
        $a52 = "'t3DU'" ascii
        $a53 = "'u2nY'" ascii
        $a54 = "'u3rY'" ascii
        $a55 = "'uhjV'" ascii
        $a56 = "'x19L'" ascii
        $a57 = "'x2nV'" ascii
        $a58 = "'x2v4'" ascii
        $a59 = "'y29U'" ascii
        $a60 = "'y2f0'" ascii
        $a61 = "'y2fJ'" ascii
        $a62 = "'y2fS'" ascii
        $a63 = "'y3j5'" ascii
        $a64 = "'y3jL'" ascii
        $a65 = "'y3rP'" ascii
        $a66 = "'yNjV'" ascii
        $a67 = "'yvjL'" ascii
        $a68 = "'yw1L'" ascii
        $a69 = "'ywjS'" ascii
        $a70 = "'yxjY'" ascii
        $a71 = "'yxrL'" ascii
        $a72 = "'yxvS'" ascii
        $a73 = "'z2v0'" ascii
        $a74 = "'z3ng'" ascii
        $a75 = "'zMLS'" ascii
        $a76 = "'zMLU'" ascii
        $a77 = "'zNjV'" ascii
        $a78 = "'zNvU'" ascii
        $a79 = "'zezP'" ascii
        $a80 = "'zfvj'" ascii
        $a81 = "'zgvM'" ascii
        $a82 = "'zhvS'" ascii
        $a83 = "'zw51'" ascii
        $a84 = "'zw5H'" ascii
        $a85 = "'zw5N'" ascii
        $a86 = "'zwf0'" ascii
        $a87 = "'zwn0'" ascii
        $a88 = "'zxjP'" ascii
        $a89 = "'zxnJ'" ascii
    condition:
        20 of them
}

/* 군집2 — 대형 번들 3건 (13b97596f4, 2a2030dc58, 4f608c4144), 각 약 142KB.
   공유 상수 11개. 군집 안 최소 11 · 군집 밖 최대 0.
   군집1 보다 교집합이 작아 임계값 여유가 좁다(0 < 6 <= 11). */
private rule evilai_locust_strarray_bundle
{
    meta:
        family    = "meadowlocust"
        samples   = 3
        shared    = 11
        threshold = 6
    strings:
        $b00 = "'AtfQ'" ascii
        $b01 = "'Dg9t'" ascii
        $b02 = "'DhjP'" ascii
        $b03 = "'DxjS'" ascii
        $b04 = "'EKXu'" ascii
        $b05 = "'ruz0'" ascii
        $b06 = "'stfo'" ascii
        $b07 = "'wvDw'" ascii
        $b08 = "'ww1n'" ascii
        $b09 = "'yMfZ'" ascii
        $b10 = "'zty0'" ascii
    condition:
        6 of them
}

/* rc4 계열 — 5건. 검체끼리 상수를 1개밖에 공유하지 않는다(빌드마다 키가
   다르다). 그래서 상수가 아니라 **세 가지 골격의 논리곱**으로 잡는다:
     $alpha  커스텀 base64 알파벳 (소문자 선행)
     $cff    제어흐름 평탄화 디스패처
     $rc4key `이름:0x숫자, 이름:'4글자'` 형태의 키 객체 — 8회 이상
   셋 다 있는 정상 파일은 코퍼스 25,853개 중 0개였다. 하나만으로는 쓰지
   않는다 — $alpha 단독은 이 난독화기를 쓴 모든 파일에 걸린다. */
private rule evilai_locust_rc4_flattened
{
    meta:
        family  = "meadowlocust"
        samples = 5
    strings:
        $alpha  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=" ascii
        $cff    = /\]\s*\|\|\s*\{\}\s*;\s*continue\s*;\s*case/
        $rc4key = /[A-Za-z_$][A-Za-z0-9_$]{0,20}\s*:\s*0x[0-9a-f]{2,4}\s*,\s*[A-Za-z_$][A-Za-z0-9_$]{0,20}\s*:\s*'[^']{4}'/
    condition:
        $alpha and $cff and #rc4key >= 8
}

/* 플러그인이 참조하는 이름. 설계-04 §2 의
   `{ yara: "rules/evilai.yar:evilai_locust_js" }` 가 이것이다. */
rule evilai_locust_js
{
    meta:
        family      = "meadowlocust"
        description = "EvilAI (Locust) 드롭 JavaScript 페이로드"
        reference   = "VirusTotal engines:meadowlocust"
    condition:
        evilai_locust_strarray_loader
        or evilai_locust_strarray_bundle
        or evilai_locust_rc4_flattened
}
