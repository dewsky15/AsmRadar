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
    """지정된 도메인에 대해 외부 자산 스캔 파이프라인을 실행하고 결과를 DB에 적재합니다."""
    print(f"[Celery] 외부 타겟 스캔 시작: {domain}")
    
    # 1. 스캐너 구동
    run_external_pipeline(domain)
    
    # 2. 결과 파싱 (파일 경로는 external_scan.py 로직 기반 매핑)
    httpx_file = f"/app/outputs/external/{domain}_httpx.json"
    if os.path.exists(httpx_file):
        parse_httpx_results(httpx_file, domain)
        
    vuln_file = f"/app/outputs/external/{domain}_vulns.json"
    if os.path.exists(vuln_file):
        parse_nuclei_results(vuln_file)
        
    print(f"[Celery] 외부 스캔 및 결과 DB 파싱 완료: {domain}")
    return True

@app.task
def task_internal_scan(cidr: str, target_name: str="internal_office"):
    """인가된 사내망에 대해 내부 스캔 파이프라인을 실행하고 결과를 적재합니다."""
    print(f"[Celery] 내부 타겟 대역 스캔 시작: {cidr}")
    
    # 1. 내부 스캐너 구동
    run_internal_pipeline(cidr, target_name)
    
    # 2. 파싱 (간단화를 위해 httpx 및 nuclei 결과만 DB로 로드, 추후 Nmap XML 파싱 추가 가능)
    httpx_file = f"/app/outputs/internal/{target_name}_httpx.json"
    if os.path.exists(httpx_file):
        parse_httpx_results(httpx_file, target_name)
        
    vuln_file = f"/app/outputs/internal/{target_name}_vulns.json"
    if os.path.exists(vuln_file):
        parse_nuclei_results(vuln_file)
        
    print(f"[Celery] 내부 스캔 및 파싱 완료: {cidr}")
    return True

# --- Celery Beat 스케줄 등록 예시 ---
@app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    # 매일 자정 00시에 example.com 스캔 (실제는 crontab 설정 가능)
    # sender.add_periodic_task(crontab(hour=0, minute=0), task_external_scan.s('example.com'))
    pass
