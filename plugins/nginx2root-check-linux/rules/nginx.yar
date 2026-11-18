// nginx2root 점검 — 직접 빌드한 nginx 실행 파일의 판 문자열.
//
// nginx 실행 파일은 서버 판을 `nginx/<판>` 글자로 담는다(src/core/nginx.h 의 NGINX_VER — Server 머리 · 오류 쪽에 쓴다).
// 뒤 글자가 숫자가 아니어야 한다 — `1.31.8` 이 `1.31.80` 의 앞부분으로 맞지 않게.

rule nginx_version_string
{
    strings:
        $v = /nginx\/[0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3}[^0-9]/
    condition:
        $v
}

// 영향 범위(nginx.org 공지 · 2026-11-19): 0.5.33 이상이고 1.30.7 아래(1.29.x · legacy 1.28.x 이하는 고친 판이 없다) ·
// 또는 1.31.0 ~ 1.31.8. 고친 판은 mainline 1.31.9 와 stable 1.30.7 이다.
rule nginx_version_affected
{
    strings:
        $v = /nginx\/(0\.5\.(3[3-9]|[4-9][0-9])|0\.[6-9]\.[0-9]{1,3}|1\.([0-9]|1[0-9]|2[0-9])\.[0-9]{1,3}|1\.30\.[0-6]|1\.31\.[0-8])[^0-9]/
    condition:
        $v
}
