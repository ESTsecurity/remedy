---
section: rules
rules: [php-2026-11-check-linux]
---
* **패키지 기록에 없는 PHP 실행 파일 · 모듈과 epoch 가 붙은 PHP 패키지의 확인 필요 표시** (Linux)\
  패키지 기록에 없는 PHP 실행 파일 · 모듈의 이름에 버전이 붙었거나(`/usr/local/bin/php8.3` · `/usr/local/bin/php83` · 어느 패키지도 깔지 않은 `/usr/bin/php8.3` · 패키지가 깔았지만 dpkg 기록(`.md5sums`)이 지워진 파일 · 어느 패키지도 깔지 않은 Apache 모듈 `/usr/lib/apache2/modules/libphp7.so`), 어느 패키지도 깔지 않은 `/usr/bin/php-fpm` 이 있거나(RHEL 9 계열처럼 `/usr/sbin` 이 따로인 기계에서 패키지가 깐 `/usr/sbin/php-fpm` 이 없을 때), PHP 패키지(dpkg 의 `php8.2-cli` · RPM 의 `php-cli` 등) 버전 앞에 `1:` 같은 번호(epoch)가 붙어(예: `1:8.2.35-1~deb12u1` · `1:8.2.35-1.el9`) 고친 버전과 견주지 못하면 *확인 필요* 로 알립니다. 이전 버전은 이런 경우 *취약한 곳을 찾지 못했습니다* 로 끝날 수 있었습니다. dpkg 의 지원이 끝난 계열(8.1 이하)은 epoch 가 붙어도 전처럼 *취약* 입니다.
