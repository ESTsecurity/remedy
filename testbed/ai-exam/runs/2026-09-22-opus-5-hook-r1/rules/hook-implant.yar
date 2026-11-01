/*
    분석가가 검체에서 도출한 룰 — hook-implant.

    **응시자는 이 파일을 고치지 않는다.** 위협 설명만으로는 다시 만들 수 없는
    것이고(파일 안의 표지 문자열), 고치면 조용히 안 맞게 된다.

    이 저장소에는 실검체가 없다. 픽스처가 세우는 파일은 크기와 표지 문자열만
    맞춘 무해한 자리 채우기이며 함수 본문이 비어 있어 아무것도 하지 않는다 —
    그래서 이 룰은 "그 표지가 한 파일에 모여 있는가" 만 본다.
*/

rule hook_implant_marks
{
    meta:
        description = "BuildKit 훅 폴더에 끼어든 스크립트의 표지 셋"
        threat = "hook-implant"

    strings:
        $mark  = "HX-9F2A-CHUNKED" ascii
        $stage = "bkt-stage-2" ascii
        $entry = "collectAndPost" ascii

    condition:
        all of them
}
