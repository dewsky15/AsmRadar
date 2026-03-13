# ASM Platform - 단일 동작 테스트 방법론 (Manual Testing Guide)

이 문서는 본격적인 스케줄러(API/Cron) 연동 이전에, **스캐너 컨테이너가 정상적으로 빌드되었는지**, 그리고 **작성된 파이썬 스캐닝 스크립트가 도구들을 올바르게 호출하는지** 수동으로 검증하기 위한 가이드입니다.

## 1. 환경 빌드 및 컨테이너 기동

먼저 Ubuntu(Hyper-V) 터미널에서 전체 환경을 빌드하고 백그라운드 대기 상태로 띄웁니다.

```bash
# 1. 최신 코드로 빌드 및 백그라운드 실행
docker-compose up -d --build

# 2. 컨테이너 3개(asm_scanner, asm_db, asm_redis)가 모두 Up 상태인지 확인
docker ps 
```

## 2. 스캐너 컨테이너 진입

`asm_scanner`는 `tail -f /dev/null` 상태로 사용자의 명령을 기다리고 있습니다. 터미널을 열어 이 내부로 침투합니다.

```bash
docker exec -it asm_scanner bash
```
> 프롬프트가 `root@ubuntu-vm:/app#` 형태로 변경되면 성공적으로 진입한 것입니다. 
> 이 내부는 Go 스캐너들과 Python 코드들이 모두 준비된 상태입니다.

---

## 3. 테스트 시나리오 1: 도구 단독 실행 테스트 (Raw Command)

파이썬 코드 도움 없이 도구 자체가 정상적으로 설치되었는지(경로, 버그 유무) 검증합니다.

```bash
# 1. 서브도메인 탐지 (외부망)
subfinder -d example.com -silent

# 2. 내부망 로우소켓 권한 확인 (내부망)
# 자신의 호스트 인터페이스에서 에러 없이 0.0.0.0/8 대역이 찔러지는지 확인
masscan 10.0.0.0/24 -p80 --rate 100 
```

---

## 4. 테스트 시나리오 2: Python 자동화 파이프라인 엔진 검증

우리가 작성한 Python 코드(`app/scanner/*.py`)가 위 도구들을 잘 엮어서 실행하고, 결과물을 `./outputs/` 디렉토리에 잘 떨구는지 검증합니다.

### 4.1 External 스캐너 파이프라인 (도메인 -> 취약점)
단일 도메인을 입력으로 주면 5개의 툴이 연쇄적으로 동작하는지 확인합니다.

```bash
# 개발한 Python 스크립트 단독 실행
python3 /app/app/scanner/external_scan.py
```
* **기대 결과**:
  1. `=== Starting External ASM Pipeline... ===` 메시지 출력
  2. `outputs/external/example.com_dnsx.json` 등 중간 산출물 파일 지속 생성
  3. `Outputs/external/example.com_vulns.json` 생성 후 종료

### 4.2 DB 연동 및 파싱 검증 (PostgreSQL Insert)
발견된 텍스트 로그들을 읽어서 Bridge 네트워크 너머에 있는 DB(`asm_db`) 테이블에 정상적으로 밀어 넣는지 테스트합니다.

```bash
# DB 스키마 생성 테스트 (처음 한번)
python3 -m app.database.init_db

# 파서 단구동 테스트 (External Pipeline 완료 후)
python3 -m app.pipeline.asset_parser
```

---

## 5. (옵션) 로컬 볼륨(Volumes) 마운트 확인

컨테이너 밖으로 빠져나와(exit), 컨테이너 안에서 생성된 파일들이 호스트(본인 PC)에도 잘 동기화되었는지 확인합니다.

```bash
exit   # 컨테이너 탈출
ls -al ./data/outputs/external/
```
*   `example.com_subdomains.txt`, `example.com_vulns.json` 등이 호스트 디렉토리에 잘 남아있다면 **완벽하게 성공**한 것입니다.
