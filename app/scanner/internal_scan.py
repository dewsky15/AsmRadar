import json
import os
import subprocess
import argparse
import sys
import logging
from pathlib import Path

# 모듈 경로 추가
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from app.pipeline.asset_parser import parse_httpx_results
from app.pipeline.vuln_parser import parse_nuclei_results

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# 출력물 저장을 위한 디렉토리 보장
OUTPUT_DIR = Path("/app/outputs/internal")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def run_command(cmd, shell=False):
    """서브프로세스를 실행하고 리턴 코드를 체크합니다."""
    try:
        # masscan 등은 root 권한이나 특수 권한이 필요하므로 stderr를 잘 봐야 함
        result = subprocess.run(cmd, shell=shell, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"[-] Command failed: {e.cmd}")
        logger.error(f"[-] Error output: {e.stderr}")
        return False

def run_masscan(cidr: str, prefix: str) -> str:
    """초고속 대역 스캔을 수행하여 활성화된 호스트와 주요 포트를 식별합니다."""
    logger.info(f"[*] Running Masscan for {cidr}...")
    out_file = OUTPUT_DIR / f"{prefix}_masscan.txt"
    cmd = [
        "masscan", cidr,
        "-p21,22,23,80,443,445,3389,8080,8443",
        "--rate", "500",
        "-oG", str(out_file)
    ]
    if run_command(cmd):
        return str(out_file)
    return ""

def parse_masscan_ips(masscan_file: str, prefix: str) -> str:
    """Masscan Grepable 포맷에서 IP 주소만 유니크하게 추출합니다."""
    ip_list_file = OUTPUT_DIR / f"{prefix}_live_ips.txt"
    ips = set()
    if os.path.exists(masscan_file):
        with open(masscan_file, "r") as f:
            for line in f:
                if line.startswith("Host:"):
                    parts = line.split(" ")
                    if len(parts) >= 2:
                        ips.add(parts[1])
                        
    with open(ip_list_file, "w") as f:
        for ip in ips:
            f.write(ip + "\n")
    return str(ip_list_file)

def run_nmap_deep_scan(ip_list_file: str, prefix: str) -> str:
    """살아있는 내부 IP에 대해 정밀 서비스/OS 배너 그랩을 수행합니다."""
    logger.info("[*] Running Nmap Deep Scan...")
    out_file = OUTPUT_DIR / f"{prefix}_nmap.xml"
    cmd = [
        "nmap", "-iL", ip_list_file,
        "-sV", "-O", "-T3",
        "-oX", str(out_file)
    ]
    if run_command(cmd):
        return str(out_file)
    return ""

def run_internal_httpx(ip_list_file: str, prefix: str) -> str:
    """내부망 내에 동작 중인 웹 관리자 페이지 등을 스니핑합니다."""
    logger.info("[*] Running httpx for internal web discovery...")
    out_file = OUTPUT_DIR / f"{prefix}_httpx.json"
    cmd = ["httpx", "-l", ip_list_file, "-title", "-tech-detect", "-status-code", "-silent", "-t", "10", "-json", "-o", str(out_file)]
    if run_command(cmd):
        return str(out_file)
    return ""

def run_internal_nuclei(httpx_out_file: str, prefix: str) -> str:
    """내부 프라이빗망용 취약점 스캔 (Default Password, RCE 등 위주)"""
    logger.info("[*] Running Nuclei for internal assets...")
    out_file = OUTPUT_DIR / f"{prefix}_vulns.json"
    target_urls = OUTPUT_DIR / f"{prefix}_target_urls.txt"
    
    # httpx JSON에서 URL 추출
    try:
        with open(httpx_out_file, 'r') as f_in, open(target_urls, 'w') as f_out:
            for line in f_in:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    if 'url' in data:
                        f_out.write(data['url'] + '\n')
                except Exception: pass
    except Exception as e:
        logger.error(f"[-] Failed to prepare targets for internal nuclei: {e}")
        return ""

    cmd = ["nuclei", "-l", str(target_urls), "-tags", "default-login,rce,misconfig,iot", "-silent", "-jsonl", "-rl", "20", "-c", "5", "-o", str(out_file)]
    if run_command(cmd):
        return str(out_file)
    return ""

def run_internal_pipeline(cidr: str, target_name: str="internal_corp"):
    """내부망 CIDR 대역에 대한 파이프라인 스캔을 통제합니다."""
    logger.info(f"=== Starting Internal ASM Pipeline for {cidr} ===")
    
    masscan_res = run_masscan(cidr, target_name)
    if not masscan_res:
        logger.warning("[-] Masscan failed. Host discovery aborted.")
        return

    ip_list = parse_masscan_ips(masscan_res, target_name)
    if not os.path.exists(ip_list) or os.path.getsize(ip_list) == 0:
        logger.warning("[-] No active internal IPs found. Pipeline terminated.")
        return
        
    # Nmap 정밀 스캔 실행 (결과는 현재 XML 파일로 보관)
    run_nmap_deep_scan(ip_list, target_name)
    
    # 웹 서비스 탐지
    httpx_res = run_internal_httpx(ip_list, target_name)
    if httpx_res:
        # [자동화] 자산 DB 적재 (내부망 플래그 활성화)
        parse_httpx_results(httpx_res, target_name, is_internal=True)
        
        # 취약점 스캔
        vuln_res = run_internal_nuclei(httpx_res, target_name)
        if vuln_res:
            # [자동화] 취약점 DB 적재
            parse_nuclei_results(vuln_res)
            logger.info(f"=== Pipeline Completed for {cidr} ===")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Internal ASM Scanner Engine")
    parser.add_argument("target", help="Target CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument("--name", default="internal_scan", help="Scan job name for output files")
    args = parser.parse_args()
    
    run_internal_pipeline(args.target, args.name)
