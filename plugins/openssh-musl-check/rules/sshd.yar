// sshd 설정에서 비밀번호 로그인을 끄는 줄 — openssh-musl-check 가 쓴다.
//
// 줄 머리의 공백 뒤 `PasswordAuthentication` 과 `no` 다. 주석(`#`)으로 시작하는 줄은 아니다. sshd 는 키워드와 값
// 사이에 공백이나 `=` 를 받고 키워드의 대소문자를 가리지 않는다. Match 블록 안의 줄인지는 가리지 않는다 — 룰이
// 그 경우를 확인 필요로 돌린다.
rule sshd_password_authentication_off
{
    meta:
        description = "a sshd_config line that turns password authentication off"
    strings:
        $off = /(^|\n)[ \t]*PasswordAuthentication([ \t]+|[ \t]*=[ \t]*)no[ \t]*(\r?\n|$)/ nocase
    condition:
        $off
}
