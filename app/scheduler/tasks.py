import os
from celery import Celery

from app.scanner.external_scan import run_pipeline as run_external_pipeline
from app.scanner.internal_scan import run_internal_pipeline

from app.pipeline.asset_parser import parse_httpx_results
from app.pipeline.vuln_parser import parse_nuclei_results

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

app = Celery("asm_tasks", broker=REDIS_URL, backend=REDIS_URL)

@app.task
def task_external_scan(domain: str):
    """지정된 도메인에 대해 외부 자산 스캔 파이프라인을 실행합니다 (내부에서 자동 파싱 수행)."""
    print(f"[Celery] 외부 타겟 스캔 시작: {domain}")
    try:
        run_external_pipeline(domain)
        print(f"[Celery] 외부 자산 스캔 파이프라인 완료: {domain}")
        return True
    except Exception as e:
        print(f"[Celery] 외부 스캔 중 에러 발생: {e}")
        return False

@app.task
def task_internal_scan(cidr: str, target_name: str="internal_office"):
    """인가된 사내망에 대해 내부 스캔 파이프라인을 실행합니다 (내부에서 자동 파싱 수행)."""
    print(f"[Celery] 내부 타겟 대역 스캔 시작: {cidr}")
    try:
        run_internal_pipeline(cidr, target_name)
        print(f"[Celery] 내부 자산 스캔 파이프라인 완료: {cidr}")
        return True
    except Exception as e:
        print(f"[Celery] 내부 스캔 중 에러 발생: {e}")
        return False

# --- Celery Beat 스케줄 등록 예시 ---
@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    # 매일 자정 00시에 example.com 스캔 (실제는 crontab 설정 가능)
    # sender.add_periodic_task(crontab(hour=0, minute=0), task_external_scan.s('example.com'))
    pass
