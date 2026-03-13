# Phase 3: Integration & Unified ASM Platform 컨테이너 구축

이 문서는 Phase 1(외부 자산)과 Phase 2(내부 자산)에서 생성된 데이터를 통합하고 자동화하는 '플랫폼 구성' 단계를 다룹니다.
데이터베이스, 캐시, API 서버, 워커 프로세스는 Host 네트워크를 쓰는 스캐너와 달리 **완전히 격리된 내장 가상 네트워크(Bridge)** 를 사용하여 보안을 극대화합니다.

## 1. 하이브리드 Docker Compose 설계

`docker-compose.yml` 리포지토리에 스캐너 외의 다양한 인프라 컴포넌트를 정의합니다. 

```yaml
version: '3.8'

services:
  # 1. 스캐너 컴포넌트 (Host Network 사용) - ASM 데이터 수집 담당
  scanner-node:
    build: 
      context: .
      dockerfile: docker/Dockerfile.scanner
    container_name: asm_scanner
    network_mode: "host"    # <--- 네트워크 성능 100% (격리 예외)
    # ...생략...

  # 2. 통합 데이터베이스 (격리된 Bridge 망 사용) - 마스터 인벤토리
  db:
    image: postgres:15-alpine
    container_name: asm_db
    restart: always
    environment:
      POSTGRES_USER: asm_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}  # .env로 보호
      POSTGRES_DB: asm_db
    ports:
      - "127.0.0.1:5432:5432"  # 호스트(Ubuntu)에서만 접근 가능하도록 바인딩
    volumes:
      - pgdata:/var/lib/postgresql/data
  
  # 3. 비동기 Task Queue (격리된 Bridge 망 사용)
  redis:
    image: redis:7-alpine
    container_name: asm_redis
    restart: always
    ports:
      - "127.0.0.1:6379:6379"

  # 4. API & 데이터 파이프라인 워커 (향후 구축)
  platform-api:
    build:
      context: .
      dockerfile: docker/Dockerfile.api
    container_name: asm_platform
    depends_on:
      - db
      - redis

volumes:
  pgdata:
```

## 2. 통합 인벤토리 (Master DB) 스키마 초기화

컨테이너가 기동된 후 데이터베이스 초기화를 자동화합니다. 
`app/database/models.py` 기반으로 구축된 SQLAlchemy 구조를 적용합니다.

```bash
# 로컬에서 UV (Python 패키지 매니저)를 사용하여 스크립트 실행 또는
# platform-api 컨테이너 내에서 실행
docker exec -it asm_platform python -m app.database.init_db
```
*   `assets`: JSONB 필드를 포함하여 동적인 포트/취약점 정보 저장
*   `scan_history`: 차분 탐지를 위한 시계열 기록

## 3. Worker (Task Queue) 통신 및 자동화

이러한 하이브리드 아키텍처에서는 스캐너(Host Net)와 DB(Bridge Net) 간의 통신이 매우 중요합니다.
`scanner-node`는 `localhost:5432`나 `localhost:6379`를 통해 호스트에 바인딩된 DB와 Redis 포트를 직접 호출(통신)할 수 있도록 코드가 구성되어야 합니다.

*   `Celery`를 사용하여 주기적인 스케줄링(예: 매일 자정 Subdomain 스캔, 주간 Nmap 스캔)을 Task Queue(Redis)에 담습니다.
*   `scanner-node` 컨테이너가 이 Queue를 소비(Consume)하여 실제 패킷 스캔을 진행하고 결과를 생성합니다.

## 4. 변경 탐지 및 알림 엔진 연동 (Alert)

스캔이 종료될 때마다 `diff_engine.py` (Platform 컨테이너)가 전일(`T-1`)과 금일(`T`)의 데이터베이스 상태를 비교합니다.

```bash
# Slack Alert 환경 설정 (보안 격리)
echo "SLACK_WEBHOOK_URL=https://hooks.slack.com/services/..." >> .env

# 알림 테스트 예시
docker exec -it asm_platform python -m app.pipeline.alert_sender --test "T-1 vs T Diff Detection Completed."
```

## 5. 단계 마무리 및 이점

이로써 `Docker Compose` 명세서 하나만으로 **의존성 꼬임 없는 외부/내부 스캐너 인프라**와 **보안이 격리된 통합 ASM 데이터 로드 플랫폼**을 모두 가질 수 있게 되었습니다. 테스트 완료 후 배포나 삭제가 필요할 때는 `docker-compose down -v` 만으로 어떤 잔여물도 남기지 않고 초기화할 수 있습니다.
