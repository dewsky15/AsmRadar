import json
import os
import subprocess
import argparse
import sys
import logging
from pathlib import Path

# 모듈 경로 추가 (부모 디렉토리의 app 패키지 참조를 위해)
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
OUTPUT_DIR = Path("/app/outputs/external")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def run_command(cmd, shell=False):
    """서브프로세스를 실행하고 리턴 코드를 체크합니다."""
    try:
        result = subprocess.run(cmd, shell=shell, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"[-] Command failed: {e.cmd}")
        logger.error(f"[-] Error output: {e.stderr}")
        return False

def run_subfinder(domain: str) -> str:
    """도메인을 받아 서브도메인을 탐지합니다. 
    결과가 없더라도 입력된 도메인 자체는 항상 포함시킵니다."""
    logger.info(f"[*] Running Subfinder for {domain}...")
    out_file = OUTPUT_DIR / f"{domain}_subdomains.txt"
    
    # 1. Subfinder 실행
    cmd = ["subfinder", "-d", domain, "-silent", "-o", str(out_file)]
    run_command(cmd)
    
    # 2. 결과 파일에 입력 도메인 자체가 없으면 추가 (최소 1개 자산 보장)
    existing_subs = set()
    if out_file.exists():
        with open(out_file, "r") as f:
            existing_subs = {line.strip() for line in f if line.strip()}
    
    if domain not in existing_subs:
        with open(out_file, "a") as f:
            f.write(domain + "\n")
            
    return str(out_file)

def run_dnsx(subdomains_file: str, domain: str) -> str:
    """서브도메인의 살아있는 IP를 해석합니다."""
    logger.info("[*] Running dnsx for DNS resolution...")
    out_file = OUTPUT_DIR / f"{domain}_dnsx.json"
    cmd = f"cat {subdomains_file} | dnsx -silent -a -cname -j -o {out_file}"
    if run_command(cmd, shell=True):
        return str(out_file)
    return ""

def run_naabu(ip_list_file: str, domain: str) -> str:
    """IP 리스트 기반 포트 스캐닝을 수행합니다."""
    logger.info("[*] Running Naabu for port scanning...")
    out_file = OUTPUT_DIR / f"{domain}_ports.json"
    cmd = ["naabu", "-l", ip_list_file, "-top-ports", "100", "-silent", "-json", "-o", str(out_file)]
    if run_command(cmd):
        return str(out_file)
    return ""

def run_httpx(port_list_file: str, domain: str) -> str:
    """열린 포트에 대해 웹 서비스를 프로파일링 합니다."""
    logger.info("[*] Running httpx for web profiling...")
    out_file = OUTPUT_DIR / f"{domain}_httpx.json"
    cmd = ["httpx", "-l", port_list_file, "-title", "-tech-detect", "-status-code", "-silent", "-json", "-o", str(out_file)]
    if run_command(cmd):
        return str(out_file)
    return ""

def run_nuclei_external(httpx_out_file: str, domain: str) -> str:
    """발견된 웹 자산에 대해 고위험군 취약점 스캔을 수행합니다."""
    logger.info("[*] Running Nuclei for vulnerability scanning...")
    out_file = OUTPUT_DIR / f"{domain}_vulns.json"
    target_urls = OUTPUT_DIR / f"{domain}_target_urls.txt"
    
    try:
        with open(httpx_out_file, 'r') as f_in, open(target_urls, 'w') as f_out:
            for line in f_in:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    if 'url' in data:
                        f_out.write(data['url'] + '\n')
                except Exception:
                    pass
    except FileNotFoundError:
        logger.error(f"[-] HTTPX output not found for nuclei: {httpx_out_file}")
        return ""

    cmd = ["nuclei", "-l", str(target_urls), "-tags", "cve,exposed-panel,default-login", "-severity", "critical,high", "-silent", "-jsonl", "-o", str(out_file)]
    if run_command(cmd):
        return str(out_file)
    return ""

def run_pipeline(domain: str):
    """지정된 도메인에 대해 전체 외부망 스캔 파이프라인을 실행합니다."""
    logger.info(f"=== Starting External ASM Pipeline for {domain} ===")
    
    # 1. 서브도메인 탐지
    subs_file = run_subfinder(domain)
    if not subs_file or not os.path.exists(subs_file) or os.path.getsize(subs_file) == 0:
        logger.error("[-] Subdomain collection failed unexpectedly.")
        return

    # 2. DNS 해석
    dnsx_file = run_dnsx(subs_file, domain)
    if not dnsx_file or not os.path.exists(dnsx_file) or os.path.getsize(dnsx_file) == 0:
        logger.error("[-] DNS resolution failed or no live hosts found.")
        return
    
    # Live IP 추출
    live_ips_file = OUTPUT_DIR / f"{domain}_live_ips.txt"
    with open(dnsx_file, 'r') as f_in, open(live_ips_file, 'w') as f_out:
        for line in f_in:
            if not line.strip(): continue
            try:
                data = json.loads(line)
                if 'a' in data:
                    for ip in data['a']:
                        f_out.write(ip + '\n')
            except Exception:
                pass

    # 3. 포트 스캔
    if os.path.exists(live_ips_file) and os.path.getsize(live_ips_file) > 0:
        ports_file = run_naabu(str(live_ips_file), domain)
        
        # [Fallback] Naabu가 포트를 못 찾은 경우, 기본 웹 포트(80, 443) 강제 추가
        hostport_file = OUTPUT_DIR / f"{domain}_hostports.txt"
        
        if not ports_file or not os.path.exists(ports_file) or os.path.getsize(ports_file) == 0:
            logger.warning("[-] No open ports found by Naabu. Applying fallback (80, 443)...")
            with open(live_ips_file, 'r') as f_in, open(hostport_file, 'w') as f_out:
                for line in f_in:
                    ip = line.strip()
                    if ip:
                        f_out.write(f"{ip}:80\n")
                        f_out.write(f"{ip}:443\n")
        else:
            # Naabu 결과가 있는 경우 정상 파싱
            logger.info(f"[+] Naabu found open ports. Generating hostports list...")
            with open(ports_file, 'r') as f_in, open(hostport_file, 'w') as f_out:
                for line in f_in:
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        f_out.write(f"{data['host']}:{data['port']}\n")
                    except Exception:
                        pass
        
        # 4. 웹 프로파일링
        if os.path.exists(hostport_file) and os.path.getsize(hostport_file) > 0:
            httpx_file = run_httpx(str(hostport_file), domain)
            if httpx_file and os.path.exists(httpx_file) and os.path.getsize(httpx_file) > 0:
                # [자동화] 자산 파싱 및 DB 적재
                logger.info("[*] Ingesting HTTPX results into database...")
                parse_httpx_results(httpx_file, domain)
                
                # 5. 취약점 스캔
                vuln_file = run_nuclei_external(httpx_file, domain)
                if vuln_file and os.path.exists(vuln_file) and os.path.getsize(vuln_file) > 0:
                    # [자동화] 취약점 파싱 및 DB 적재
                    logger.info("[*] Ingesting Nuclei results into database...")
                    parse_nuclei_results(vuln_file)
                    logger.info(f"=== Pipeline Completed for {domain} ===")
                else:
                    logger.info(f"[-] No vulnerabilities found for {domain} (or Nuclei failed)")
            else:
                logger.warning("[-] No web services identified by httpx.")
    else:
        logger.warning("[-] No live IPs to scan ports.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="External ASM Scanner Engine")
    parser.add_argument("domain", help="Target domain to scan")
    args = parser.parse_args()
    
    run_pipeline(args.domain)
