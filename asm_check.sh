#!/bin/bash

# 색상 정의
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}     ASM Platform Health Check UI      ${NC}"
echo -e "${BLUE}=======================================${NC}\n"

# 1. Docker 컨테이너 상태 점검
echo -e "${YELLOW}[1] Docker Containers Status${NC}"

check_container() {
    local container_name=$1
    if [ "$(docker ps -q -f name=$container_name)" ]; then
        echo -e " - $container_name : ${GREEN}[ Running ]${NC}"
    else
        echo -e " - $container_name : ${RED}[ Stopped / Error ]${NC}"
    fi
}

check_container "asm_scanner"
check_container "asm_db"
check_container "asm_redis"
echo ""

# 2. Scanner 도구 설치 검증 (asm_scanner 내부)
echo -e "${YELLOW}[2] Scanner Tools Verification${NC}"

check_tool() {
    local tool_name=$1
    local check_cmd=$2
    
    # 컨테이너 내부에 명령어를 던져서 성공(0)하면 OK
    docker exec asm_scanner bash -c "$check_cmd" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e " - $tool_name : ${GREEN}[ Ready ]${NC}"
    else
        echo -e " - $tool_name : ${RED}[ Not Found / Error ]${NC}"
    fi
}

# 컨테이너가 켜져있을 때만 도구 검사 수행
if [ "$(docker ps -q -f name=asm_scanner)" ]; then
    check_tool "Subfinder" "subfinder -version"
    check_tool "DNSx" "dnsx -version"
    check_tool "Naabu" "naabu -version"
    check_tool "HTTPx" "httpx -version"
    check_tool "Nuclei" "nuclei -version"
    check_tool "Masscan" "masscan -V"
    check_tool "Nmap" "nmap --version"
else
    echo -e "${RED} [!] asm_scanner 컨테이너가 꺼져 있어 도구 검사를 건너뜁니다.${NC}"
fi

echo ""

# 3. 네트워크 권한 (Raw Socket) 점검
echo -e "${YELLOW}[3] Network & Permission Check${NC}"
if [ "$(docker ps -q -f name=asm_scanner)" ]; then
    # Masscan이 에러 없이 실행되는지 (권한 확인)
    docker exec asm_scanner bash -c "masscan 127.0.0.1 -p80 --rate 10 > /dev/null 2>&1"
    if [ $? -eq 0 ]; then
        echo -e " - Raw Socket Permission : ${GREEN}[ OK ]${NC}"
        echo -e " - Host Network Mode     : ${GREEN}[ OK ]${NC}"
    else
        echo -e " - Raw Socket Permission : ${RED}[ Failed ]${NC} (Check cap_add or sudo)"
    fi
else
    echo -e "${RED} [!] asm_scanner 컨테이너 미동작${NC}"
fi

echo -e "\n${BLUE}=======================================${NC}"
echo -e " Health Check Completed."
