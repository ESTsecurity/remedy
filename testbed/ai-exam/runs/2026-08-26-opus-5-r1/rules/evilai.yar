rule evilai_locust_js
{
    meta:
        description = "EvilAI (Locust) 난독화 JS 페이로드"
        source = "testbed/ai-exam THREAT.md 의 관측 항목"

    strings:
        // 실행 직전 base64 복원
        $b64 = "Buffer.from(" ascii nocase
        $b64_tag = "'base64'" ascii nocase
        $b64_tag2 = "\"base64\"" ascii nocase

        // 외부 명령 실행
        $cp = "child_process" ascii nocase
        $exec = "exec(" ascii

        // 문자열 배열을 인덱스로 꺼내 쓰는 난독화
        $arr = /var _0x[0-9a-f]{4,6}\s*=\s*\[/ ascii nocase
        $arr2 = /_0x[0-9a-f]{4,6}\s*\(\s*0x[0-9a-f]+/ ascii nocase

    condition:
        // 난독화 흔적과 실행 경로가 함께 있어야 한다. 하나만으로는
        // 정상 번들 산출물과 갈라지지 않는다.
        filesize < 4MB
        and any of ($arr*)
        and (
            (any of ($b64*) and $b64)
            or ($cp and $exec)
        )
}
