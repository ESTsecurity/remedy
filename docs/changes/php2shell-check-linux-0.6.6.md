---
section: rules
rules: [php2shell-check-linux, remedy-net-criteria]
---
* **다시 지은 공식 Docker 이미지 PHP 8.3.37 인식** (Linux)\
  2026-11-24 에 다시 지은 공식 Docker 이미지 `php:8.3.37` · `8.3.37-cli` · `8.3.37-fpm` · `8.3.37-apache` 로 올린 PHP 를 고친 버전으로 판정합니다. 이전 버전은 공식 빌드의 해시와 맞지 않는다며 *확인 필요* 로 알렸습니다. 2026-11-19 에 지은 이미지도 이전과 같이 고친 버전으로 판정합니다.

<details>
<summary><b>알아두실 점 및 자세한 내용 보기</b></summary>

* 공식 Docker 이미지는 기반 이미지가 바뀔 때마다 다시 지어져 해시가 바뀝니다 — 이번 이미지 뒤에 다시 지은 이미지는 룰이 그 해시를 더할 때까지 *확인 필요* 로 나옵니다.
* 이미지 파일 · 컨테이너 점검(`remedy-net`)의 판정 기준은 이번에도 바뀌지 않아, 그 점검에서 `php:8.3.37` 이미지는 *확인 필요* 입니다.
* 자세한 내용은 https://github.com/ESTsecurity/remedy/blob/main/docs/%EC%9C%84%ED%98%91%EB%B3%84-%EC%95%88%EB%82%B4.md#php2shell 에 있습니다.

</details>
