import json
import os
import subprocess
from pathlib import Path

# 출력물 저장을 위한 디렉토리 보장
OUTPUT_DIR = Path("/app/outputs/external")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def run_subfinder(domain: str) -> str:
    """도메인을 받아 서브도메인을 탐지합니다."""
    print(f"[*] Running Subfinder for {domain}...")
    out_file = OUTPUT_DIR / f"{domain}_subdomains.txt"
    # -silent: 배너 숨김
    cmd = ["subfinder", "-d", domain, "-silent", "-o", str(out_file)]
    subprocess.run(cmd, check=False)
    return str(out_file)

def run_dnsx(subdomains_file: str, domain: str) -> str:
    """서브도메인의 살아있는 IP를 해석합니다."""
    print("[*] Running dnsx for DNS resolution...")
    out_file = OUTPUT_DIR / f"{domain}_dnsx.json"
    # JSON 형태로 결과 출력 (-j)
    cmd = f"cat {subdomains_file} | dnsx -silent -a -cname -j -o {out_file}"
    subprocess.run(cmd, shell=True, check=False)
    return str(out_file)

def run_naabu(ip_list_file: str, domain: str) -> str:
    """IP 리스트 기반 포트 스캐닝을 수행합니다."""
    print("[*] Running Naabu for port scanning...")
    out_file = OUTPUT_DIR / f"{domain}_ports.json"
    # top 100 ports example
    cmd = ["naabu", "-l", ip_list_file, "-top-ports", "100", "-silent", "-json", "-o", str(out_file)]
    subprocess.run(cmd, check=False)
    return str(out_file)

def run_httpx(port_list_file: str, domain: str) -> str:
    """열린 포트에 대해 웹 서비스를 프로파일링 합니다."""
    print("[*] Running httpx for web profiling...")
    out_file = OUTPUT_DIR / f"{domain}_httpx.json"
    cmd = ["httpx", "-l", port_list_file, "-title", "-tech-detect", "-status-code", "-silent", "-json", "-o", str(out_file)]
    subprocess.run(cmd, check=False)
    return str(out_file)

def run_nuclei_external(httpx_out_file: str, domain: str) -> str:
    """발견된 웹 자산에 대해 고위험군 취약점 스캔을 수행합니다."""
    print("[*] Running Nuclei for vulnerability scanning...")
    out_file = OUTPUT_DIR / f"{domain}_vulns.json"
    # 추출된 URL 목록을 바탕으로 파싱 스캔. (ex. cve, exposed-panels, default-login)
    target_urls = OUTPUT_DIR / f"{domain}_target_urls.txt"
    
    # httpx JSON에서 URL만 추출하여 임시 파일에 저장
    with open(httpx_out_file, 'r') as f_in, open(target_urls, 'w') as f_out:
        for line in f_in:
            if not line.strip(): continue
            try:
                data = json.loads(line)
                if 'url' in data:
                    f_out.write(data['url'] + '\n')
            except Exception:
                pass

    cmd = ["nuclei", "-l", str(target_urls), "-tags", "cve,exposed-panel,default-login", "-severity", "critical,high", "-silent", "-jsonl", "-o", str(out_file)]
    subprocess.run(cmd, check=False)
    return str(out_file)

def run_pipeline(domain: str):
    """지정된 도메인에 대해 전체 외부망 스캔 파이프라인을 실행합니다."""
    print(f"=== Starting External ASM Pipeline for {domain} ===")
    
    subs_file = run_subfinder(domain)
    
    if not os.path.exists(subs_file) or os.path.getsize(subs_file) == 0:
        print("[-] 서브도메인을 발견하지 못했습니다. 파이프라인 종료.")
        return

    dnsx_file = run_dnsx(subs_file, domain)
    
    # DNSX 결과에서 라이브 IP만 추출
    live_ips_file = OUTPUT_DIR / f"{domain}_live_ips.txt"
    with open(dnsx_file, 'r') as f_in, open(live_ips_file, 'w') as f_out:
        for line in f_in:
            if not line.strip(): continue
            try:
                data = json.loads(line)
                if 'a' in data: # IP(A 레코드)가 있는 경우
                    for ip in data['a']:
                        f_out.write(ip + '\n')
            except Exception:
                pass

    if os.path.exists(live_ips_file) and os.path.getsize(live_ips_file) > 0:
        ports_file = run_naabu(str(live_ips_file), domain)
        
        # Naabu 결과에서 ip:port 추출
        hostport_file = OUTPUT_DIR / f"{domain}_hostports.txt"
        with open(ports_file, 'r') as f_in, open(hostport_file, 'w') as f_out:
            for line in f_in:
                if not line.strip(): continue
                try:
                    data = json.loads(line)
                    f_out.write(f"{data['host']}:{data['port']}\n")
                except Exception:
                    pass
        
        if os.path.exists(hostport_file) and os.path.getsize(hostport_file) > 0:
            httpx_file = run_httpx(str(hostport_file), domain)
            vuln_file = run_nuclei_external(httpx_file, domain)
            print(f"=== Pipeline Completed. Vulnerabilities saved to {vuln_file} ===")

if __name__ == "__main__":
    # Test Run
    run_pipeline("example.com")
