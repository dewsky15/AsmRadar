# Phase 2: Internal Attack Surface Management (ASM) 통합망 스캔

이 문서는 조직 내부망(Internal Network)에 존재하는 호스트 및 취약점을 능동적으로 스캔하는 단계를 다룹니다. Phase 1에서 생성한 `scanner-node` 컨테이너는 이미 `network_mode: "host"`로 구성되어 있으므로, 가상 네트워크(NAT) 병목 및 IP 스푸핑 제약 없이 호스트 환경과 100% 동일한 **고속 로우 소켓(Raw Socket) 스캔**이 가능합니다.

## 1. 사전 요구사항

*   Phase 1의 `docker-compose up -d` 환경 빌드 완료
*   스캔을 실행할 컨테이너 내부 진입 권한
*   **인가된 내부망 스캔 범위 목록 (CIDR Format) 보유**
*   로컬 호스트(Hyper-V Ubuntu)가 사내망 IP 대역과 통신 가능한(Bridged) 네트워크 상태인지 확인

## 2. Masscan 빌드 및 추가 구성 (Dockerfile 업데이트)

Masscan은 내부의 광활한 대역(예: `10.0.0.0/8`)을 스캔하기 위해 필요합니다. Phase 1의 `Dockerfile.scanner`에 다음 줄을 추가하여 Masscan을 컨테이너 내부에 빌드해 둡니다.

```dockerfile
# (Dockerfile.scanner 내부 추가)
# Masscan 설치 (초고속 대역 스캐너)
RUN git clone https://github.com/robertdavidgraham/masscan /tmp/masscan && \
    cd /tmp/masscan && make -j4 && make install && \
    rm -rf /tmp/masscan
```
*코드 수정 후 `docker-compose build`를 통해 이미지를 최신화합니다.*

## 3. 내부 스캔 파이프라인 구성 및 테스트

Masscan과 Nmap은 `network_mode: "host"` 의 진가를 발휘하는 도구들입니다. 외부를 거치지 않고 직접 내부 IP와 통신하여 패킷 누락을 방지합니다.

### 3.1 광범위 네트워크 활성 대역 스캔 (Discovery)
스캐너 컨테이너에 접속하여 사내망 탐지를 실행합니다.

```bash
# asm_scanner 컨테이너 접속
docker exec -it asm_scanner bash

# 1. 내부망 서브넷(예: 192.168.1.0/24) 고속 포트(Port) 점검
# --rate 1000 : 초당 1000패킷 (사내 방화벽 부하 경감을 위해 보수적 설정)
masscan 192.168.1.0/24 -p21,22,23,80,443,445,3389,8080 -oG outputs/internal_masscan.txt --rate 1000
```
*저장된 통합 로그 `outputs/internal_masscan.txt` 폴더는 마운트된 로컬 경로(`data/outputs`)에서 직접 열람할 수 있습니다.*

### 3.2 심층 포트 및 OS 지문 분석 (Nmap)
발견된 활성 IP에 대해 정밀한 서비스 프로파일링을 덧붙입니다. 컨테이너는 마치 로컬 서버인 것처럼 Nmap 커널 핑(`-PE`) 및 OS 탐지(`-O`) 옵션을 제약 없이 수행합니다.

```bash
# 2. 정밀 서비스 스캔
# (주의: masscan 로그에서 필터링된 IP 리스트 ip_list.txt를 사전에 파싱)
nmap -iL outputs/ip_list.txt -sV -sC -O -oX outputs/internal_nmap.xml
```

### 3.3 내부 Web 프로파일링 및 서버 취약점 탐지
내부망에만 존재하는 관리자 대시보드 및 백오피스를 식별하고 기본 취약점을 탐지합니다.

```bash
# 3. 내부 웹 서비스 식별
cat outputs/internal_web_ports.txt | httpx -title -tech-detect -status-code -o outputs/internal_web.txt

# 4. 내장 템플릿(RCE, 기본 암호 유출 등)기반 고위험 취약점 스캔
cat outputs/internal_web.txt | nuclei -tags cve,default-login,rce,misconfig -o outputs/internal_vulns.txt
```

## 4. 보안 및 스캔 운영 가이드 (권고안)
*   **스캐너 고정 IP 인식 (White-Listing)**
    현재 하이브리드 컨테이너 아키텍처에서는, 스캐너 컨테이너가 밖으로 내보내는 패킷의 출발지 IP(Source IP)가 **호스트(Ubuntu VM)의 IP와 완전히 일치합니다.** 
    IDS/IPS 팀이나 네트워크 팀과 협의하여 **해당 Host VM의 IP 하나만 화이트리스트 처리**받으면 컨테이너 내부 환경의 독립적인 롤백성과 스캐너의 자유로운 네트워크 권한을 동시에 보장받을 수 있습니다.
*   **Rate-Limiting (가용성 보장)**
    내장된 구형 스위치나 내부망의 IoT/ICS 장비들은 지나친 UDP/TCP SYN Flood 수준의 패킷에 셧다운(Dos)될 수 있습니다. `Masscan`과 `Nuclei`의 쓰레드(`-c`), 초당 패킷(`-rate-limit`) 옵션은 언제나 보스적인 수치 이하로 관리되어야 합니다.
