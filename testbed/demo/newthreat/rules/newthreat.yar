/* 시연 9단계의 "새 위협" 룰 — 일곱 줄.
 *
 * 검체가 아니라 **시연용 표식**이다. 대본이 게스트에서
 *   "DEMO-NEW-THREAT-MARKER payload" > helper.dat
 * 를 만들어 이 룰이 발화하게 한다. */
rule demo_newthreat
{
    strings:
        $a = "DEMO-NEW-THREAT-MARKER"
    condition:
        $a
}
