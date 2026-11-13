// Apache HTTP/2 점검(apache-http2-check-linux)이 쓰는 본문 규칙 — 설정 줄 둘과 직접 빌드 실행 파일의 판 하나.
//
// 설정 줄은 줄 머리의 공백 뒤에서 시작하는 것만 센다 — 주석(`#`)으로 시작하는 줄은 아니다. Apache 는 지시어 이름의
// 대소문자를 가리지 않는다. <IfModule> · <VirtualHost> 안의 줄인지는 가리지 않는다 — 룰이 머신 전체의 흔적으로 쓴다.
rule apache_h2_loadmodule
{
    meta:
        description = "an active LoadModule line that loads mod_http2"
    strings:
        $load = /(^|\n)[ \t]*LoadModule[ \t]+http2_module[ \t]/ nocase
    condition:
        $load
}

// `Protocols` 의 값 가운데 h2 · h2c 낱말. 값은 공백으로 나뉘고 순서는 상관없다(`Protocols http/1.1 h2`).
// `ProtocolsHonorOrder` 는 다른 지시어다 — `Protocols` 바로 뒤에 공백이 와야 한다.
rule apache_h2_protocols
{
    meta:
        description = "an active Protocols line that offers h2 or h2c"
    strings:
        $p = /(^|\n)[ \t]*Protocols[ \t]([^\r\n#]*[ \t])?h2c?([ \t\r\n]|$)/ nocase
    condition:
        $p
}

// 직접 빌드한 httpd 의 서버 판 문자열 `Apache/2.4.x` — 실행 파일에 NUL 로 끝나는 C 문자열로 박힌다(배포판 빌드 다섯에서
// 확인: Debian 12 · Ubuntu 22.04 · Rocky 9 · Amazon Linux 2023 · Alpine 3.22). 영향 범위는 2.4.55 ~ 2.4.70 이다.
rule apache_version_affected
{
    meta:
        description = "the Apache/2.4.55 - 2.4.70 server version string in an httpd binary"
    strings:
        $v = /Apache\/2\.4\.(5[5-9]|6[0-9]|70)[^0-9]/
    condition:
        $v
}
