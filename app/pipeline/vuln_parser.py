import json
import logging
from sqlalchemy.orm import Session

from app.database.init_db import SessionLocal
from app.database.models import Vulnerability, Port, IPAddress

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_nuclei_results(file_path: str):
    """
    Nuclei 스캔 JSONL 결과를 읽어 취약점(Vulnerability) 테이블에 적재합니다.
    """
    logger.info(f"파싱 시작: Nuclei 결과 파일 [{file_path}]")
    
    db: Session = SessionLocal()
    
    try:
        with open(file_path, "r") as f:
            for line in f:
                if not line.strip(): continue
                
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                host = data.get("host", "")  # IP or domain
                port_num = 0
                
                # "https://example.com:8443/xxx" 형태 등에서 도메인 및 포트 추출 로직 (단순화 버전)
                if ":" in host and not host.startswith("http"):
                    parts = host.split(":")
                    host_ip = parts[0]
                    if parts[1].isdigit():
                        port_num = int(parts[1])
                elif host.startswith("http"):
                    from urllib.parse import urlparse
                    parsed = urlparse(host)
                    host_ip = parsed.hostname
                    port_num = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)
                else:
                    host_ip = host
                
                # 1. IP 매핑 찾기
                ip_obj = db.query(IPAddress).filter(IPAddress.address == host_ip).first()
                port_obj = None
                
                if ip_obj and port_num > 0:
                    port_obj = db.query(Port).filter(Port.ip_id == ip_obj.id, Port.port_number == port_num).first()
                
                # DB에 자산 정보가 없더라도 (연결이 끊기더라도) 일단 취약점 자체는 남기도록 구성
                vuln_name = data.get("info", {}).get("name", "Unknown Vulnerability")
                severity = data.get("info", {}).get("severity", "info")
                desc = data.get("info", {}).get("description", "")
                
                # 중복 취약점(동일 자산, 동일 템플릿) 검사
                if port_obj:
                    existing = db.query(Vulnerability).filter(
                        Vulnerability.port_id == port_obj.id,
                        Vulnerability.vuln_name == vuln_name
                    ).first()
                    
                    if existing:
                        existing.raw_data = data  # 업데이트
                        continue
                
                new_vuln = Vulnerability(
                    port_id=port_obj.id if port_obj else None,
                    tool_name="nuclei",
                    vuln_name=vuln_name,
                    severity=severity,
                    description=desc,
                    raw_data=data
                )
                db.add(new_vuln)
                
        db.commit()
        logger.info("[+] 취약점(Nuclei) 파싱 및 DB 적재 완료.")
        
    except Exception as e:
        logger.error(f"[-] 취약점 적재 중 오류 발생: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    pass
