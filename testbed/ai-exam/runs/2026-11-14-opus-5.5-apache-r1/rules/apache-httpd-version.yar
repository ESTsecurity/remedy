// apache-http2-check-linux — 직접 빌드한 httpd 의 서버 판 문자열(AP_SERVER_BASEVERSION)
// 영향 범위 2.4.55 ~ 2.4.70 (CVE-2026-119618) · 고친 판 2.4.71.
// 판 뒤에 숫자가 아닌 글자를 요구해 2.4.5 · 2.4.700 같은 꼴을 잡지 않는다.
// plugin.yaml 의 build_vuln 이 일곱 접두사의 bin/httpd 에만 건다 — 전역에 풀지 않는다.
rule apache_httpd_2_4_55_to_2_4_70
{
    strings:
        $ver = /Apache\/2\.4\.(5[5-9]|6[0-9]|70)[^0-9]/
    condition:
        $ver
}
