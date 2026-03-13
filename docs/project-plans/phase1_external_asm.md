# Phase 1: External Attack Surface Management (ASM) 컨테이너 구축

이 문서는 조직의 인터넷 노출 자산을 자동으로 식별하고 취약점을 스캔하는 'External ASM' 파이프라인의 구축 방법을 설명합니다. 로컬 환경의 오염을 방지하고 완벽한 호환성을 유지하기 위해 **모든 스캐너와 도구는 단일 Docker Compose 환경 내에 컨테이너화**되어 실행됩니다.

## 1. 아키텍처 설계 (하이브리드 컨테이너)

보안 스캐닝 도구(`Naabu`, `Masscan` 등)는 다량의 Raw Socket 패킷을 생성하므로, 기본 Docker Bridge 네트워크에 두면 NAT 오버헤드로 인해 속도가 저하되고 패킷이 누락됩니다.
이를 해결하기 위해 스캐너 컨테이너에만 **Host Network(`network_mode: "host"`)** 권한을 부여하여 100% 네이티브 성능을 끌어냅니다.

## 2. Scanner Dockerfile 작성

다양한 OS 의존성(Go 패키지, libpcap 등)을 한 곳에 모은 `Dockerfile.scanner`를 작성합니다. 베이스 이미지는 호환성이 높고 Nmap/Masscan 빌드 환경을 구축하기 쉬운 `ubuntu:24.04`를 사용합니다.

`docker/Dockerfile.scanner`:
```dockerfile
FROM ubuntu:24.04

# 필수 시스템 패키지 설치
RUN apt-get update && apt-get install -y \
    wget curl git gcc make clang libpcap-dev nmap python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Go 언어 다운로드 및 설치 (최신 버전 사용 권장)
ENV GO_VERSION=1.22.1
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

# 정찰 및 취약점 진단 도구 설치 (ProjectDiscovery)
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Nuclei 템플릿 업데이트 및 다운로드
RUN nuclei -ut

WORKDIR /app
COPY . /app/
```

## 3. Docker Compose 구성 (스캐너 파트)

`docker-compose.yml` 파일에 스캐너 서비스를 선언합니다.

```yaml
version: '3.8'

services:
  # 외부/내부 자산을 스캔하는 워커(Worker) 컨테이너
  scanner-node:
    build: 
      context: .
      dockerfile: docker/Dockerfile.scanner
    container_name: asm_scanner
    # [핵심] 호스트 OS(Ubuntu VM)의 네트워크 스택을 직접 사용하여 성능 병목 및 NAT 이슈 제거
    network_mode: "host"
    environment:
      - DB_HOST=localhost  # host 네트워크를 사용하므로 DB 컨테이너 접근 시 고려 필요
    volumes:
      - ./data/outputs:/app/outputs:rw
    # 기본적으로 실행을 유지시켜 필요할 때마다 명령을 내리도록 설정
    command: tail -f /dev/null
```

## 4. 파이프라인 실행 및 설치 검증

### 4.1 환경 빌드 및 구동
로컬(Ubuntu) 터미널 환경에서 다음 명령어를 통해 깔끔하게 설치 및 실행합니다.

```bash
# Docker Compose 백그라운드 구동 (자동 빌드 포함)
docker-compose up -d --build

# 실행 상태 확인
docker ps | grep asm_scanner
```

### 4.2 스캔 테스트 (Dry Run)
가동된 스캐너 컨테이너(`asm_scanner`) 내부로 접속하여 도메인 탐지 파이프라인이 정상적으로 파이프되는지 테스트합니다.

```bash
# asm_scanner 컨테이너 내부로 Bash 접속 (로컬 환경 오염 X)
docker exec -it asm_scanner bash

# 컨테이너 내부에서 실행: 도메인 발견부터 취약점 스캔까지 단일 라인 처리
subfinder -d example.com -silent | dnsx -silent -resp-only | naabu -p 80,443 -silent | httpx -title -status-code -tech-detect -silent > outputs/external_results.txt
```

위의 결과물은 컨테이너 내부가 아닌 로컬의 `data/outputs` 디렉토리(볼륨 마운트)에 안전하게 저장됩니다.

## 5. 다음 단계
위의 인프라는 모든 정찰 도구를 완벽히 세팅하고 잦은 환경 구축/삭제에 대응하기 위한 기초 공사입니다. 이어지는 **Phase 2**에서는 동일한 `scanner-node` 컨테이너를 사용하여 내부망(Internal)을 고속으로 스캔하는 방법을 다룹니다.
