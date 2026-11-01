/*
   evilai.yar — EvilAI (Locust) 계열 JavaScript 페이로드
   분석가가 검체에서 도출해 룰 작성자에게 넘기는 파일이다. 손으로 고치지 말 것.

   ── 검체가 어떻게 생겼나 ────────────────────────────────────────────────
   전부 문자열배열 난독화이고 **평문 IOC 가 하나도 없다** — URL·도메인·경로가
   0건이다. 그래서 이 룰은 인코딩된 상수와 골격을 겨눈다.

   문자열 배열은 커스텀 알파벳 base64 다(소문자가 앞에 온다). 키가 없으므로
   같은 평문은 언제나 같은 상수가 된다. 풀면 require / process /
   createDecipheriv / aes / hex / zlib / readFileSync 가 나온다 — AES 복호 +
   zlib 해제 로더다.

   ── 임계값 ─────────────────────────────────────────────────────────────
   군집마다 "군집 안 최소 개수" 와 "군집 밖 최대 개수" 를 재고 그 사이에
   두었다.

   ── 실측 ───────────────────────────────────────────────────────────────
   탐지   검체                16 / 16
   오탐   호스트 청정 .js      0 / 25,863   (VS Code · Node 런타임 · node_modules 3벌)
   오탐   VM 청정 .js          0 /  3,750
   오탐   타 패밀리 검체 25종   0 /    625

   ── 남는 위험 — 반드시 읽을 것 ─────────────────────────────────────────
   rc4 룰은 악성코드가 아니라 **난독화기**의 골격을 겨눈다. 같은 도구·같은
   설정으로 난독화한 정상 소프트웨어는 원리상 걸릴 수 있다. 위 코퍼스에서
   0건이었을 뿐 "세상에 없다" 는 뜻이 아니다.

   **이 룰을 시스템 전역 스캔에 그대로 쓰면 안 된다.** 악성 판정된 증거가
   가리키는 디렉터리 안에서만 돌려야 그 위험이 실질적으로 막힌다.
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
