# AsmRadar (Attack Surface Management)

[🇺🇸 English](README_EN.md) | [🇰🇷 한국어](README.md)

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![Docker](https://img.shields.io/badge/docker-ready-green)

This project is a containerized ASM pipeline **developed in collaboration with an AI Agent**. It leverages intelligent automation to discover and manage attack surfaces across hybrid network environments.

## 🚀 Key Features & Architecture (Phases)

This platform is structured around a 4-phase architecture to provide end-to-end asset and vulnerability management.

### Phase 1: External ASM
- **Asset Discovery**: `Subfinder`, `Amass`, `dnsx` to resolve domains and subdomains.
- **Service Discovery**: `Naabu` for ultra-fast port scanning on discovered IPs.
- **Web Identification**: `httpx` to profile web technologies, status codes, and titles.
- **Vulnerability Scanning**: `Nuclei` for automated baseline vulnerability detection (CVEs, misconfigs).

### Phase 2: Internal ASM
- **Network Discovery**: `Masscan` and `Nmap` integration for rapid discovery of internal CIDR ranges.
- **Internal Service & Web Enumeration**: Profiling internal endpoints (SMB, RDP, SSH) and internal web services.
- **Internal Vuln Scan**: Running internal security audits strictly within the permitted network scope.

### Phase 3: Integration Platform
- **Asset Database**: PostgreSQL backend storing highly structured normalization data (`JSONB`).
- **Data Pipeline**: Automated parsing of JSON outputs from multiple disparate scanners into a unified relational schema (Domain -> Subdomain -> IP -> Port -> Vulnerability).

### Phase 4: Automation & Scheduling
- **Task Queue**: Fully asynchronous `Celery` + `Redis` worker nodes for non-blocking periodic scans.
- **Dockerized Hybrid Network**: `Host` network mode for the scanner engine (to prevent bottleneck & NAT issues) and `Bridge` network for database/Redis isolation.

---

## ⚙️ Prerequisites

- **OS**: Linux (Ubuntu 24.04 recommended) or Windows 11 with WSL2 / Hyper-V Ubuntu VM
- **Docker & Docker Compose**
- **Hardware**: Minimum 4 Cores CPU, 8GB RAM

## 🛠️ Quick Start (One-Click Deployment)

1. **Clone the repository**
   ```bash
   git clone https://github.com/dewsky15/AsmRadar.git
   cd AsmRadar
   ```

2. **Configure Environment Variables**
   ```bash
   cp .env.example .env
   # Edit .env with your specific configurations
   ```

3. **Build and Run the Infrastructure**
   ```bash
   docker-compose up -d --build
   ```

4. **Verify Health Status**
   ```bash
   chmod +x asm_check.sh
   ./asm_check.sh
   ```

## 🎯 Usage (CLI)

You can easily dispatch scanning jobs using the integrated Python CLI.

```bash
# External Scan (Domain)
python3 asm_cli.py -t example.com -m external

# Internal Scan (CIDR)
python3 asm_cli.py -t 10.0.0.0/24 -m internal
```

## 📝 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
