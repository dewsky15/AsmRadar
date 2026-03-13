#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os

def print_banner():
    banner = """
    ===================================================
      [ ASM Platform Automated Scanner CLI ]
    ===================================================
    """
    print(banner)

def run_in_container(command: str):
    """docker exec를 통해 asm_scanner 컨테이너 내부에서 명령어를 실행합니다."""
    docker_cmd = ["docker", "exec", "-t", "asm_scanner", "bash", "-c", command]
    try:
        # 실시간 출력 표출
        process = subprocess.Popen(docker_cmd, stdout=sys.stdout, stderr=sys.stderr)
        process.wait()
        if process.returncode != 0:
            print(f"\n[-] Error: Command failed with exit code {process.returncode}")
    except FileNotFoundError:
        print("\n[-] Error: Docker is not installed or not in PATH.")

def main():
    parser = argparse.ArgumentParser(description="ASM Platform CLI Endpoint")
    parser.add_argument("-t", "--target", required=True, help="Target Domain (External) or CIDR (Internal)")
    parser.add_argument("-m", "--mode", required=True, choices=['external', 'internal'], help="Scan mode: external(Domain) or internal(CIDR)")
    
    args = parser.parse_args()
    print_banner()
    
    print(f"[*] Target : {args.target}")
    print(f"[*] Mode   : {args.mode}")
    print("[*] Dispatching job to 'asm_scanner' container...\n")
    
    if args.mode == "external":
        # 컨테이너 내부에 작성해둔 파이썬 엔진 호출 (타겟 동적 주입)
        cmd = f"python3 /app/app/scanner/external_scan.py {args.target}" 
        run_in_container(cmd)
        
    elif args.mode == "internal":
        cmd = f"python3 /app/app/scanner/internal_scan.py {args.target}"
        run_in_container(cmd)

if __name__ == "__main__":
    main()
