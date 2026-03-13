import os
import subprocess
from pathlib import Path

# 출력물 저장을 위한 디렉토리 보장
OUTPUT_DIR = Path("/app/outputs/internal")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def run_masscan(cidr: str, prefix: str) -> str:
    """초고속 대역 스캔을 수행하여 활성화된 호스트와 주요 포트를 식별합니다."""
    print(f"[*] Running Masscan for {cidr}...")
    out_file = OUTPUT_DIR / f"{prefix}_masscan.txt"
    # rate 1000 패킷/sec 제한, 주요 포트 타겟팅
    cmd = [
        "masscan", cidr,
        "-p21,22,23,80,443,445,3389,8080,8443",
        "--rate", "1000",
        "-oG", str(out_file)
    ]
    subprocess.run(cmd, check=False)
    return str(out_file)

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
    print("[*] Running Nmap Deep Scan...")
    out_file = OUTPUT_DIR / f"{prefix}_nmap.xml"
    # -iL : 리스트 읽기, -sV : 서비스 버전, -O : OS 탐지, -T3 : 일반적 속도
    cmd = [
        "nmap", "-iL", ip_list_file,
        "-sV", "-O", "-T3",
        "-oX", str(out_file)
    ]
    subprocess.run(cmd, check=False)
    return str(out_file)

def run_internal_httpx(ip_list_file: str, prefix: str) -> str:
    """내부망 내에 동작 중인 웹 관리자 페이지 등을 스니핑합니다."""
    print("[*] Running httpx for internal web discovery...")
    out_file = OUTPUT_DIR / f"{prefix}_httpx.json"
    cmd = ["httpx", "-l", ip_list_file, "-title", "-tech-detect", "-status-code", "-silent", "-json", "-o", str(out_file)]
    subprocess.run(cmd, check=False)
    return str(out_file)

def run_internal_nuclei(httpx_out_file: str, prefix: str) -> str:
    """내부 프라이빗망용 취약점 스캔 (Default Password, RCE 등 위주)"""
    print("[*] Running Nuclei for internal assets...")
    out_file = OUTPUT_DIR / f"{prefix}_vulns.json"
    
    # httpx JSON에서 URL 추출을 위한 편의성 커맨드 (jq가 없으므로 awk/sed 쓰거나 파이썬 자체 파싱 권장)
    target_urls = OUTPUT_DIR / f"{prefix}_target_urls.txt"
    subprocess.run(f"cat {httpx_out_file} | grep '\"url\"' | awk -F'\"url\":\"' '{{print $2}}' | awk -F'\"' '{{print $1}}' > {target_urls}", shell=True)

    cmd = ["nuclei", "-l", str(target_urls), "-tags", "default-login,rce,misconfig,iot", "-silent", "-jsonl", "-o", str(out_file)]
    subprocess.run(cmd, check=False)
    return str(out_file)

def run_internal_pipeline(cidr: str, target_name: str="internal_corp"):
    """내부망 CIDR 대역에 대한 파이프라인 스캔을 통제합니다."""
    print(f"=== Starting Internal ASM Pipeline for {cidr} ===")
    
    masscan_res = run_masscan(cidr, target_name)
    ip_list = parse_masscan_ips(masscan_res, target_name)
    
    if not os.path.exists(ip_list) or os.path.getsize(ip_list) == 0:
        print("[-] 활성화된 내부 IP를 찾을 수 없습니다. 파이프라인 종료.")
        return
        
    run_nmap_deep_scan(ip_list, target_name)
    
    # 포트스캔과 별개로, 내부망의 웹 서비스 프로파일링도 IP 기반으로 던짐(httpx가 80/443 알아서 체크)
    httpx_res = run_internal_httpx(ip_list, target_name)
    vuln_res = run_internal_nuclei(httpx_res, target_name)
    print(f"=== Pipeline Completed. Vulnerabilities saved to {vuln_res} ===")

if __name__ == "__main__":
    # Test Run (Local Docker Bridge 등 아주 작은 대역만 타겟팅)
    run_internal_pipeline("172.17.0.0/24")
