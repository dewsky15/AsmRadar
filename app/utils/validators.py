import re

def is_valid_ip(address: str) -> bool:
    """IP 주소 형식인지 확인합니다. (IPv4 지원)"""
    if not address:
        return False
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, address.strip()))
