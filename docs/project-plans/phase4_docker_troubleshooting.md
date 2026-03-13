# Phase 4: ASM Docker 환경 운영 및 트러블슈팅 가이드

이 문서는 하이브리드 아키텍처(Host Network + Bridge Network) 기반의 ASM 플랫폼을 운영할 때 필요한 **Docker 권장 설정, 성능 튜닝, 그리고 자주 발생하는 오류 해결 방법**을 다룹니다.

## 1. 최적의 Docker 실행 권한 설정

ASM 스캐너 컨테이너(`scanner-node`)가 호스트 네트워크 스택을 온전히 사용하고 로컬 패킷 전송을 위해 적절한 권한을 가지도록 설정해야 합니다.

*   **`sudo` 없이 Docker 실행하기 (권장)**:
    매번 `sudo docker-compose`를 입력하는 번거로움을 줄이고, 파일 권한(Permission) 꼬임을 방지합니다.
    ```bash
    sudo usermod -aG docker $USER
    newgrp docker
    ```

*   **Capabilities 부여 (선택사항)**:
    `network_mode: "host"`로 구동되는 스캐너 컨테이너는 이미 대부분의 호스트 권한을 공유하지만, `Nmap`의 `-sS`(SYN Stealth Scan) 등을 사용할 때 캡처 에러가 발생하면 `docker-compose.yml` 리스트에 다음을 추가하세요.
    ```yaml
    scanner-node:
      ...
      # 패킷 생성(Raw Socket) 및 조작 권한 명시적 부여
      cap_add:
        - NET_ADMIN
        - NET_RAW
    ```

## 2. 권장 리소스(CPU/Memory) 튜닝

`Nuclei` (수만 개의 템플릿 스캔) 및 `Masscan` (초당 수천 패킷)은 컨테이너에 심각한 부하를 유발할 수 있습니다. 

*   **Ubuntu VM 자체 할당량**: 최소 4 vCPU, 8GB RAM (다다익선)
*   **Docker Daemon 최적화**: 너무 많은 스레드가 열릴 경우 "Too many open files" 에러가 발생합니다.
    *   해결책: 호스트(Ubuntu)의 `/etc/security/limits.conf` 수정
    ```text
    * soft nofile 65535
    * hard nofile 65535
    ```

*   **OOM(Out Of Memory) 킬러 방지**: 
    스캐닝 결과물(JSON/XML) 메모리 버퍼링으로 인해 컨테이너가 뻗어버릴 수 있습니다. `docker-compose.yml`에 안전장치를 둡니다.
    ```yaml
    scanner-node:
      ...
      deploy:
        resources:
          limits:
            memory: 6G    # 컨테이너가 넘지 못할 최대 메모리
            cpus: '3.0'   # 전체 CPU 코어 중 최대 3개까지만 사용
    ```

## 3. 자주 발생하는 오류 및 해결 방법 (Troubleshooting)

### Q1. "sudo masscan ... Error: Could not find valid interface" (인터페이스 불량)
*   **원인**: 컨테이너가 올바른 네트워크 어댑터를 찾지 못했거나 가상 브리지(`docker0`)를 사용하려 할 때 발생.
*   **해결**: `network_mode: "host"` 지정 여부를 확인하고, 스캔 명령어에 명시적으로 어댑터 이름(`-e eth0`)을 부여합니다. Host OS의 메인 인터페이스 이름은 `ip addr`로 확인하세요.

### Q2. 스캔 속도가 너무 느리고 패킷이 DROP 됩니다.
*   **원인**: 사내 방화벽이나 라우터가 스캔으로 인한 세션 폭증(Stateful Firewall Limit)을 버티지 못하고 드랍하는 경우입니다.
*   **해결**: 스캐너 옵션에 반드시 Rate Limit을 걸어주세요.
    *   Masscan: `--rate 1000` (최대 3000 미만 권장)
    *   Nuclei: `-rl 50 -c 10` (초당 50 리퀘스트, 10개 동시실행으로 제한)

### Q3. "connection to server at 'db' (127.0.0.1) failed" (DB 접속 불가)
*   **원인**: `network_mode: "host"` 인 스캐너 컨테이너가 `bridge` 네트워크에 있는 `asm_db`를 `db`라는 이름으로 찾으려 할 때 발생.
*   **해결**: 스캐너는 호스트와 네트워크를 공유하므로, 호스트 입장에서 브리지 DB에 접근하는 주소인 `localhost` 또는 `127.0.0.1`를 가리켜야 합니다. 환경 변수를 `DB_HOST=127.0.0.1` 로 명시하십시오. (`DB_HOST=db`는 실패합니다.)

### Q4. "Permission denied" 결과물 저장 시 (Volumes)
*   **원인**: 로컬의 `data/outputs` 폴더와 컨테이너 내부의 사용자(UID)가 일치하지 않아 발생합니다.
*   **해결**: 로컬에서 출력 폴더 권한을 풀어주세요.
    ```bash
    mkdir -p data/outputs
    chmod 777 data/outputs
    ```
