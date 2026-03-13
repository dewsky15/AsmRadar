import json
import logging
from sqlalchemy.orm import Session

from app.database.init_db import SessionLocal
from app.database.models import Domain, Subdomain, IPAddress, Port

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_httpx_results(file_path: str, domain_name: str):
    """
    httpx 출력 결과를 읽어 Domain -> Subdomain -> IP -> Port 구조로 DB에 적재합니다.
    """
    logger.info(f"파싱 시작: httpx 결과 파일 [{file_path}]")
    
    db: Session = SessionLocal()
    
    try:
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
                    
                target_host = data.get("host", "")  # ex) admin.example.com
                
                # 2. Subdomain 생성 (IP 형태가 아니라면 서브도메인으로 취급)
                subdomain_obj = None
                if target_host and not target_host.replace(".", "").isdigit():
                    subdomain_obj = db.query(Subdomain).filter(Subdomain.name == target_host).first()
                    if not subdomain_obj:
                        subdomain_obj = Subdomain(name=target_host, domain_id=domain_obj.id)
                        db.add(subdomain_obj)
                        db.commit()
                        db.refresh(subdomain_obj)
                
                # 3. IP 확인 및 생성 (httpx가 IP를 제공하는 경우 'a' 레코드 배열 참조)
                ip_str = ""
                a_records = data.get("a", [])
                if a_records:
                    ip_str = a_records[0]
                elif target_host.replace(".", "").isdigit():
                    ip_str = target_host

                ip_obj = None
                if ip_str:
                    ip_obj = db.query(IPAddress).filter(IPAddress.address == ip_str).first()
                    if not ip_obj:
                        ip_obj = IPAddress(
                            address=ip_str, 
                            subdomain_id=subdomain_obj.id if subdomain_obj else None,
                            is_internal=False  # External 파서 기준
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
                        "server": data.get("webserver", "")
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
                        # 기존 자산 업데이트 (최신 상태 갱신)
                        port_obj.metadata_info = metadata
                    
        db.commit()
        logger.info("[+] 웹 자산(httpx) 파싱 및 DB 적재 완료.")
        
    except Exception as e:
        logger.error(f"[-] DB 적재 중 오류 발생: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    # Test
    # parse_httpx_results("/app/outputs/external/example.com_httpx.json", "example.com")
    pass
