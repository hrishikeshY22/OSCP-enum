#!/usr/bin/bash

# Define colors
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No color

# Configuration
WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
NMAP_THREADS=4
GOBUSTER_THREADS=50
NIKTO_MAXTIME=360
UDP_PORTS="--top-ports 100" # Top 100 UDP ports for scanning

# Display help menu
show_help() {
    cat << EOF
${YELLOW}Usage: $0 <target_ip> [options]${NC}
Options:
  -h, --help    Show this help message
  -u            Enable UDP port scanning
  -v            Enable verbose output
  --clean       Clean up previous results before starting
EOF
    exit 0
}

# Check for required tools
check_tools() {
    local tools=("nmap" "figlet" "nikto" "gobuster" "enum4linux")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}[ERROR] ${tool} is not installed. Please install it and re-run the script.${NC}"
            exit 1
        fi
    done
}

# Validate IP address
validate_ip() {
    local ip=$1
    if [[ ! $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}[ERROR] Invalid IP address.${NC}"
        exit 1
    fi
}

# Show script banner
show_banner() {
    figlet "OSCP Enum"
    echo -e "${CYAN}Automated Enumeration Script${NC}"
}

# Run enum4linux for SMB enumeration
run_enum4linux() {
    local ip=$1
    local output_dir=$2

    echo -e "${MAGENTA}[+] Running enum4linux for SMB enumeration...${NC}"
    enum4linux -a "$ip" > "${output_dir}/enum4linux/full_enum.txt" 2>&1

    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}[+] enum4linux results saved to ${output_dir}/enum4linux/full_enum.txt.${NC}"
    else
        echo -e "${RED}[ERROR] enum4linux failed. Check the log file for details.${NC}"
    fi
}

# Run Nmap scans
run_nmap_scan() {
    local ip=$1
    local output_dir=$2
    local udp_scan=$3

    echo -e "${MAGENTA}[+] Scanning all TCP ports and enumerating services with Nmap...${NC}"
    local tcp_scan_file="${output_dir}/nmap/tcp_scan.txt"
    nmap -p- -sV -Pn -T4 -oN "$tcp_scan_file" "$ip"

    if [[ $? -ne 0 ]]; then
        echo -e "${RED}[ERROR] Nmap TCP scan failed. Exiting.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] TCP scan completed. Results saved to $tcp_scan_file.${NC}"

    if [[ "$udp_scan" == true ]]; then
        echo -e "${MAGENTA}[+] Scanning top UDP ports with Nmap...${NC}"
        local udp_scan_file="${output_dir}/nmap/udp_scan.txt"
        nmap -sU -sV $UDP_PORTS -Pn -oN "$udp_scan_file" "$ip"
        echo -e "${GREEN}[+] UDP scan completed. Results saved to $udp_scan_file.${NC}"
    fi

    grep "open" "$tcp_scan_file" | awk '{print $1}' | cut -d'/' -f1 > "${output_dir}/nmap/open_ports.txt"
}

# Process Nmap results and run NSE scripts
process_nmap_results() {
    local ip=$1
    local output_dir=$2

    local tcp_scan_file="${output_dir}/nmap/tcp_scan.txt"
    local web_ports=()

    while IFS= read -r line; do
        port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
        service=$(echo "$line" | awk '{print $3}')

        case "$service" in
            http*|ssl/http*)
                echo -e "${BLUE}[+] Detected HTTP/HTTPS on port $port. Running HTTP-related NSE scripts...${NC}"
                web_ports+=("$port")
                nmap --script=http-enum,http-title,http-headers -p "$port" "$ip" -oN "${output_dir}/nmap/http_nse_$port.txt"
                ;;
            smb|microsoft-ds)
                echo -e "${BLUE}[+] Detected SMB on port $port. Running SMB-related NSE scripts...${NC}"
                nmap --script=smb-enum-shares,smb-enum-users,smb-vuln-ms17-010 -p "$port" "$ip" -oN "${output_dir}/nmap/smb_nse_$port.txt"
                ;;
            ftp)
                echo -e "${BLUE}[+] Detected FTP on port $port. Running FTP-related NSE scripts...${NC}"
                nmap --script=ftp-anon,ftp-bounce,ftp-syst -p "$port" "$ip" -oN "${output_dir}/nmap/ftp_nse_$port.txt"
                ;;
            ssh)
                echo -e "${BLUE}[+] Detected SSH on port $port. Running SSH-related NSE scripts...${NC}"
                nmap --script=ssh-auth-methods,ssh-hostkey,sshv1 -p "$port" "$ip" -oN "${output_dir}/nmap/ssh_nse_$port.txt"
                ;;
            smtp)
                echo -e "${BLUE}[+] Detected SMTP on port $port. Running SMTP-related NSE scripts...${NC}"
                nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344 -p "$port" "$ip" -oN "${output_dir}/nmap/smtp_nse_$port.txt"
                ;;
            dns)
                echo -e "${BLUE}[+] Detected DNS on port $port. Running DNS-related NSE scripts...${NC}"
                nmap --script=dns-recursion,dns-service-discovery -p "$port" "$ip" -oN "${output_dir}/nmap/dns_nse_$port.txt"
                ;;
            rpcbind|msrpc)
                echo -e "${BLUE}[+] Detected RPC on port $port. Running RPC-related NSE scripts...${NC}"
                nmap --script=rpc-grind,rpcinfo -p "$port" "$ip" -oN "${output_dir}/nmap/rpc_nse_$port.txt"
                ;;
            mysql)
                echo -e "${BLUE}[+] Detected MySQL on port $port. Running MySQL-related NSE scripts...${NC}"
                nmap --script=mysql-databases,mysql-info,mysql-vuln-cve2012-2122 -p "$port" "$ip" -oN "${output_dir}/nmap/mysql_nse_$port.txt"
                ;;
            postgresql)
                echo -e "${BLUE}[+] Detected PostgreSQL on port $port. Running PostgreSQL-related NSE scripts...${NC}"
                nmap --script=pgsql-brute,postgres-brute -p "$port" "$ip" -oN "${output_dir}/nmap/postgresql_nse_$port.txt"
                ;;
            vnc)
                echo -e "${BLUE}[+] Detected VNC on port $port. Running VNC-related NSE scripts...${NC}"
                nmap --script=realvnc-auth-bypass,vnc-info -p "$port" "$ip" -oN "${output_dir}/nmap/vnc_nse_$port.txt"
                ;;
            *)
                echo -e "${YELLOW}[!] Detected unknown/unsupported service ($service) on port $port. Running default scripts.${NC}"
                nmap -sC -p "$port" "$ip" -oN "${output_dir}/nmap/default_nse_$port.txt"
                ;;
        esac
    done < <(grep "open" "$tcp_scan_file")

    echo "${web_ports[@]}" > "${output_dir}/web_ports.txt"

    run_nikto "$ip" "$output_dir" "${web_ports[@]}"
    run_gobuster "$ip" "$output_dir" "${web_ports[@]}"
}

# Run Nikto scans
run_nikto() {
    local ip=$1
    local output_dir=$2
    shift 2
    local web_ports=($@)

    for port in "${web_ports[@]}"; do
        protocol="http"
        [[ "$port" == "443" ]] && protocol="https"
        echo -e "${CYAN}[+] Running Nikto on ${protocol}://${ip}:${port}...${NC}"
        nikto -h "${protocol}://${ip}:${port}" -maxtime $NIKTO_MAXTIME -output "${output_dir}/nikto/${protocol}_${port}.txt"
    done
}

# Run Gobuster
run_gobuster() {
    local ip=$1
    local output_dir=$2
    shift 2
    local web_ports=($@)

    for port in "${web_ports[@]}"; do
        protocol="http"
        [[ "$port" == "443" ]] && protocol="https"
        echo -e "${CYAN}[+] Running Gobuster on ${protocol}://${ip}:${port}...${NC}"
        gobuster dir -u "${protocol}://${ip}:${port}" -w "$WORDLIST" -t "$GOBUSTER_THREADS" -o "${output_dir}/gobuster/${protocol}_${port}.txt"
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}[ERROR] Gobuster failed on ${protocol}://${ip}:${port}. Check the output for details.${NC}"
        fi
    done
}

# Main function
main() {
    local ip=""
    local udp_scan=false
    local clean=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                show_help
                ;;
            -u)
                udp_scan=true
                ;;
            --clean)
                clean=true
                ;;
            *)
                ip="$1"
                validate_ip "$ip"
                ;;
        esac
        shift
    done

    if [[ -z "$ip" ]]; then
        echo -e "${RED}[ERROR] Target IP is required.${NC}"
        show_help
    fi

    local output_dir="enum_results_${ip}"
    if [[ "$clean" == true ]]; then
        echo -e "${YELLOW}[+] Cleaning up previous results...${NC}"
        rm -rf "$output_dir"
    fi

    mkdir -p "$output_dir/nmap" "$output_dir/gobuster" "$output_dir/enum4linux" "$output_dir/nikto"
    show_banner

    echo -e "${CYAN}[+] Starting enumeration for $ip.${NC}"
    run_nmap_scan "$ip" "$output_dir" "$udp_scan"
    process_nmap_results "$ip" "$output_dir"
    run_enum4linux "$ip" "$output_dir"
    echo -e "${GREEN}[+] Enumeration completed. Results saved in $output_dir.${NC}"
}

# Check required tools and execute main
check_tools
main "$@"
