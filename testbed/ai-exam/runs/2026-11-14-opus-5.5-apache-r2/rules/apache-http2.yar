rule apache_httpd_2_4_55_to_2_4_70
{
    meta:
        description = "Apache httpd server version string in the CVE-2026-119618 affected range (2.4.55 - 2.4.70); version must be followed by a non-digit"
    strings:
        $ver = /Apache\/2\.4\.(5[5-9]|6[0-9]|70)[^0-9]/
    condition:
        $ver
}
