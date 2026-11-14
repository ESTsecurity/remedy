// Apache HTTP/2 점검 — Windows(apache-http2-check-windows)가 쓰는 본문 규칙 — libhttpd.dll 의 서버 판 둘.
//
// 서버 판 문자열 `Apache/2.4.x` 는 libhttpd.dll 에 NUL 로 끝나는 C 문자열로 박힌다 — `Apache/2.4.71 (Win64)` 와
// `Apache/2.4.71`(Apache Lounge 2.4.71 실측 · 2026-11-14). httpd.exe 에는 없다. 상류 소스(ap_release.h)가 정한 문자열이라
// 빌드한 곳(Apache Lounge · XAMPP · WampServer · Laragon)과 무관하다.

// 영향 범위 2.4.55 ~ 2.4.70. 판 뒤에 숫자가 오면 안 된다 — `2.4.700` 같은 것을 2.4.70 으로 읽지 않는다.
rule apache_version_affected
{
    meta:
        description = "the Apache/2.4.55 - 2.4.70 server version string in libhttpd.dll"
    strings:
        $v = /Apache\/2\.4\.(5[5-9]|6[0-9]|70)[^0-9]/
    condition:
        $v
}

// 판을 읽을 수 있는가 — 어떤 2.x 의 서버 판이든. 이것이 없으면 그 빌드의 판을 모르는 것이다.
rule apache_version_any
{
    meta:
        description = "any Apache/2.x.y server version string in libhttpd.dll"
    strings:
        $v = /Apache\/2\.[0-9]+\.[0-9]+[^0-9]/
    condition:
        $v
}
