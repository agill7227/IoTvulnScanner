# IoTscan - IoT Device Vulnerability Scanner

A comprehensive IoT device vulnerability scanner written in Go, designed for network administrators and security professionals to identify and assess security risks in IoT environments.

## Features

- Network Device Discovery (ARP, SNMP, UPnP, mDNS)
- Device Fingerprinting
- Weak Password Detection
- Firmware Vulnerability Analysis
- Port and Service Scanning
- Protocol Security Analysis
- Detailed Report Generation

## Prerequisites

- Go 1.21 or higher
- libpcap development files (for packet capture)
  - Ubuntu/Debian: `sudo apt-get install libpcap-dev`
  - CentOS/RHEL: `sudo yum install libpcap-devel`
  - Windows: WinPcap or Npcap installed

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/IoTscan.git

# Change to project directory
cd IoTscan

# Install dependencies
go mod download

# Build the project
go build -o iotscan
```

## Usage

```bash
# Basic scan of local network
./iotscan scan

# Scan specific IP range
./iotscan scan --range 192.168.1.0/24

# Generate detailed report
./iotscan scan --report-format pdf --output report.pdf

# Show help
./iotscan --help
```

## Security Considerations

- This tool is intended for ethical use only
- Always obtain proper authorization before scanning networks
- Use rate limiting to avoid disrupting device operations
- Follow responsible disclosure practices for any vulnerabilities found

## License

MIT License - See LICENSE file for details 
