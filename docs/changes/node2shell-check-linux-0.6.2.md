---
section: rules
rules: [node2shell-check-linux]
---
* **배포판 Node.js 패키지가 있어도 공식 빌드가 아닌 node 를 확인 필요로 알립니다** (Linux)\
  배포판 Node.js 패키지(nodejs · libnode)가 깔린 서버에서는 패키지가 깔지 않은 자리(nvm · /opt · /usr/local/bin)의, 공식 빌드와 맞지 않는 node 를 지금까지 판정하지 않고 넘어갔습니다. 이제 그런 node 를 *확인 필요* 로 알립니다 — 그 node 의 버전과 받은 곳을 확인하고, 쓰는 계열의 고친 버전(22 는 22.23.4 · 24 는 24.22.1 · 26 은 26.12.1) 이상인지 보십시오.
