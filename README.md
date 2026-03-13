# AsmRadar (공격 표면 관리 플랫폼)

[🇺🇸 English](README_EN.md) | [🇰🇷 한국어](README.md)

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![Docker](https://img.shields.io/badge/docker-ready-green)

본 프로젝트는 **AI Agent와 협업하여 제작된** 컨테이너 기반의 자동화 파이프라인입니다. 기업의 인터넷 노출 자산과 내부망 자산을 지능적으로 식별하고 관리하는 Attack Surface Management(ASM) 인프라를 구축합니다.

## 🚀 주요 기능 및 아키텍처 (Phases)

이 플랫폼은 자산 및 취약점 관리를 자동화하기 위해 4단계(Phase) 아키텍처로 구성되어 있습니다.

### Phase 1: External ASM (인터넷 노출 자산 탐지)
- **Asset Discovery**: `Subfinder`, `Amass`, `dnsx`를 활용한 도메인 및 서브도메인 탐지.
- **Service Discovery**: 검색된 IP를 대상으로 `Naabu`를 이용한 초고속 포트 스캔.
- **Web Identification**: `httpx`를 이용해 상태 코드, 타이틀, 사용된 웹 기술(Technology) 프로파일링.
- **Vulnerability Scanning**: `Nuclei`를 이용한 기본 취약점(CVE, 잘못된 설정 등) 자동 탐지.

### Phase 2: Internal ASM (내부망 자산 식별)
- **Network Discovery**: `Masscan`과 `Nmap` 연동을 통한 내부 대역(CIDR) 초고속 자산 탐지.
- **Internal Service & Web Enumeration**: 내부 엔드포인트(SMB, RDP, SSH) 및 웹 서비스 프로파일링.
- **Internal Vuln Scan**: 인가된 내부 네트워크 범위 내에서 내부 서비스 보안 취약점 감사.

### Phase 3: Integration Platform (통합 관리)
- **Asset Database**: 정규화된 데이터 및 복잡한 속성을 처리하기 위해 `JSONB`를 활용하는 PostgreSQL 기반 데이터베이스.
- **Data Pipeline**: 각기 다른 스캐너의 JSON 결과물을 단일 관계형 모델(Domain -> Subdomain -> IP -> Port -> Vulnerability)로 자동 파싱.

### Phase 4: Automation & Scheduling
- **Task Queue**: 차단 없는 비동기 스캔을 위한 `Celery` + `Redis` 워커(Worker) 노드 구축.
- **Dockerized Hybrid Network**: 스캐너 엔진은 병목/NAT 이슈 방지를 위해 `Host` 네트워크 모드로, DB/Redis는 격리 및 보안을 위해 `Bridge` 네트워크로 구성된 하이브리드 아키텍처.

---

## ⚙️ 사전 요구 사항 (Prerequisites)

- **OS**: Linux (Ubuntu 24.04 권장) 또는 Windows 11 (WSL2 / Hyper-V Ubuntu VM)
- **Docker & Docker Compose**
- **하드웨어**: 최소 4 Core CPU, 8GB RAM

## 🛠️ 빠른 시작 (Quick Start)

1. **저장소 클론(Clone)**
   ```bash
   git clone https://github.com/dewsky15/AsmRadar.git
   cd AsmRadar
   ```

2. **환경 변수 설정**
   ```bash
   cp .env.example .env
   # .env 파일에 필요한 설정(계정, 포트 등) 입력
   ```

3. **인프라 빌드 및 실행**
   ```bash
   docker-compose up -d --build
   ```

4. **상태 진단 및 검증**
   ```bash
   chmod +x asm_check.sh
   ./asm_check.sh
   ```

## 🎯 사용 방법 (CLI)

내장된 Python CLI 래퍼를 사용하여 스캔 작업을 쉽게 지시할 수 있습니다.

```bash
# 외부망 스캔 (도메인 타겟)
python3 asm_cli.py -t example.com -m external

# 내부망 스캔 (CIDR 타겟)
python3 asm_cli.py -t 10.0.0.0/24 -m internal
```

## 📝 데모 환경 및 테스트 가이드

인프라 구성 후 파이프라인 검증 가이드는 [Manual Testing Guide](docs/project-plans/test_methodology.md)를 참고하세요.

## 📝 라이선스 (License)
본 프로젝트는 MIT 라이선스에 따라 배포됩니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참고하세요.
