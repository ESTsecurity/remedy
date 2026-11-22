---
section: rules
rules: [apache-http2-check-linux, remedy-net-criteria]
---
* **버전을 읽지 못한 직접 빌드 Apache 를 확인 필요로 알립니다** (Linux)\
  `/usr/local/apache2` · `/opt/lampp` 처럼 패키지가 깔지 않은 자리의 `httpd` 에서 버전을 읽지 못하면 지금까지는 판정하지 않고 넘어갔습니다. 이제 *확인 필요* 로 알립니다 — 그 경로의 `httpd -v` 로 버전을 확인하고, 2.4.55 ~ 2.4.70 이면 2.4.71 이상으로 올리십시오(그때까지 Protocols 에서 h2 · h2c 를 빼십시오).
