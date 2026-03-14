import json
import logging
import os
from sqlalchemy.orm import Session

from app.database.init_db import SessionLocal
from app.database.models import Domain, Subdomain, IPAddress, Port

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_valid_ip(address: str) -> bool:
    """IP 주소 형식인지 확인합니다."""
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, address.strip()))

def parse_httpx_results(file_path: str, domain_name: str, db: Session = None, is_internal: bool = False):
    """
    httpx 출력 결과를 읽어 Domain -> Subdomain -> IP -> Port 구조로 DB에 적재합니다.
    """
    logger.info(f"[*] Starting asset parsing: [{file_path}] for [{domain_name}] (internal={is_internal})")
    
    should_close = False
    if db is None:
        db = SessionLocal()
        should_close = True
    
    try:
        if not os.path.exists(file_path):
            logger.warning(f"[-] httpx result file not found: {file_path}")
            return

        # 1. 대상 도메인 확보/생성
        domain_obj = db.query(Domain).filter(Domain.name == domain_name).first()
        if not domain_obj:
            domain_obj = Domain(name=domain_name, source="httpx")
            db.add(domain_obj)
            db.commit()
            db.refresh(domain_obj)
            
        with open(file_path, "r") as f:
            for line in f:
                if not line.strip(): continue
                
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                    
                target_host = data.get("host", "").strip()
                
                # 2. Subdomain 생성 (IP 형태가 아니라면 서브도메인으로 취급)
                subdomain_obj = None
                if target_host and not is_valid_ip(target_host):
                    subdomain_obj = db.query(Subdomain).filter(Subdomain.name == target_host).first()
                    if not subdomain_obj:
                        subdomain_obj = Subdomain(name=target_host, domain_id=domain_obj.id)
                        db.add(subdomain_obj)
                        db.commit()
                        db.refresh(subdomain_obj)
                
                # 3. IP 확인 및 생성
                ip_str = ""
                a_records = data.get("a", [])
                if a_records:
                    ip_str = a_records[0]
                elif is_valid_ip(target_host):
                    ip_str = target_host

                ip_obj = None
                if ip_str:
                    ip_obj = db.query(IPAddress).filter(IPAddress.address == ip_str).first()
                    if not ip_obj:
                        ip_obj = IPAddress(
                            address=ip_str, 
                            subdomain_id=subdomain_obj.id if subdomain_obj else None,
                            is_internal=is_internal
                        )
                        db.add(ip_obj)
                        db.commit()
                        db.refresh(ip_obj)

                # 4. Port 및 웹 기술 메타데이터 저장
                port_num = int(data.get("port", 80))
                if ip_obj:
                    # 중복된 IP-Port 검사
                    port_obj = db.query(Port).filter(Port.ip_id == ip_obj.id, Port.port_number == port_num).first()
                    
                    metadata = {
                        "title": data.get("title", ""),
                        "status_code": data.get("status_code", 0),
                        "tech": data.get("tech", []),
                        "cdn": data.get("cdn", False),
                        "server": data.get("webserver", ""),
                        "last_scanned": data.get("timestamp", "")
                    }
                    
                    if not port_obj:
                        port_obj = Port(
                            ip_id=ip_obj.id,
                            port_number=port_num,
                            protocol="tcp",
                            service_name="http" if port_num in [80, 8080] else "https",
                            metadata_info=metadata
                        )
                        db.add(port_obj)
                    else:
                        port_obj.metadata_info = metadata
                    
        db.commit()
        logger.info(f"[+] Asset parsing completed for {domain_name}")
        
    except Exception as e:
        logger.error(f"[-] Error during DB ingestion: {e}")
        db.rollback()
        raise e
    finally:
        if should_close:
            db.close()

if __name__ == "__main__":
    pass
