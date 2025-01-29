# OSCP Enumeration Script

This is a Bash script designed to automate the enumeration process during penetration testing, particularly for OSCP-like scenarios. It performs comprehensive scans using tools like `nmap`, `gobuster`, `nikto`, and `enum4linux` to gather information about a target system.

---

## Features

- **Nmap Scans**:
  - Full TCP port scan with service detection.
  - Optional UDP port scan (top 100 ports).
  - Service-specific NSE scripts for common services (e.g., HTTP, SMB, FTP, SSH, SMTP, DNS, MySQL, PostgreSQL, VNC).

- **Web Enumeration**:
  - Runs `gobuster` for directory brute-forcing.
  - Runs `nikto` for web vulnerability scanning.

- **SMB Enumeration**:
  - Uses `enum4linux` for comprehensive SMB enumeration.

- **Customizable**:
  - Configurable wordlist, threads, and scan options.
  - Supports verbose output and cleanup of previous results.

---

## Prerequisites

Before using this script, ensure the following tools are installed on your system:

- `nmap`
- `gobuster`
- `nikto`
- `enum4linux`
- `figlet` (for the banner)

You can install these tools using your package manager:

```bash
# For Debian/Ubuntu-based systems
sudo apt update
sudo apt install nmap gobuster nikto enum4linux figlet
```