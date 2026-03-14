# ASM Platform - 단일 동작 테스트 방법론 (Manual Testing Guide)

이 문서는 호스트(Ubuntu/VM) 터미널에서 **스캐너 컨테이너 동작 및 파이프라인**을 즉시 검증하기 위한 가이드입니다. 모든 명령어는 복사하여 바로 실행할 수 있도록 `docker exec` 원라이너로 구성되었습니다.

---

## 1. 환경 빌드 및 상태 확인

```bash
# 1. 최신 코드로 빌드 및 컨테이너 기동
docker compose up -d --build

# 2. 모든 서비스(scanner, db, redis) 대기 상태 확인
docker compose ps
```

---

## 2. 테스트 시나리오 1: 스캐닝 도구 단독 실행 (Raw Command)

컨테이너 내부로 진입하지 않고 호스트에서 바로 도구의 작동 여부를 확인합니다.

```bash
# 1. 서브도메인 탐지 (Subfinder)
docker exec -it asm_scanner subfinder -d example.com -silent

# 2. 웹 프로파일링 (HTTPx)
docker exec -it asm_scanner bash -c "echo 'example.com' | httpx -silent -title -tech-detect"

# 3. 네트워크 스캔 권한 확인 (Masscan)
docker exec -it asm_scanner masscan 1.1.1.1 -p80 --rate 100
```

---

## 3. 테스트 시나리오 2: Python 자동화 파이프라인 검증

우리가 작성한 Python 스캐닝 엔진이 도구들을 연쇄적으로 호출하고 데이터를 저장하는지 테스트합니다.

```bash
# 1. DB 스키마 초기화 (시작 전 필수)
docker exec -it asm_scanner python3 -m app.database.init_db

# 2. External 스캔 파이프라인 실행 (도메인 기반)
docker exec -it asm_scanner python3 /app/app/scanner/external_scan.py example.com

# 3. 데이터베이스 결과 파싱 및 삽입 (스캔 완료 후)
docker exec -it asm_scanner python3 -m app.pipeline.asset_parser
```

---

## 4. 최종 결과물 마운트 확인

컨테이너 내부에서 생성된 결과 파일이 호스트의 `./data/outputs/` 디렉토리에 동기화되었는지 확인합니다.

```bash
# 외부 스캔 결과 파일 목록 확인
ls -al ./data/outputs/external/

# 취약점 스캔 결과(Nuclei) 예시 확인
cat ./data/outputs/external/example.com_vulns.json
```

---

## 💡 팁: 실시간 로그 모니터링
스캔이 진행되는 동안 컨테이너 내부에서 일어나는 일을 실시간으로 보려면 아래 명령어를 다른 터미널에 띄워두세요.
```bash
docker logs -f asm_scanner
```
