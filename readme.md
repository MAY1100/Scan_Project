# Network Scanning and Enumeration Script

## Project Overview
This Bash script automates network scanning and enumeration using **Nmap, Masscan, and Hydra**. It identifies active hosts, open ports, running services, and potential vulnerabilities. Additionally, it performs brute-force attacks on common services such as **SSH, FTP, RDP, and Telnet**. The script is designed for **Kali Linux**.

## Features
- **Automated Installation**: Installs required tools (**Nmap, Hydra, Masscan, and Searchsploit**) if missing.
- **CIDR Range Input**: Allows users to specify the network range.
- **Scan Type Selection**: Supports **Basic** (port scan, service enumeration, weak password check) and **Full** (includes NSE vulnerability scripts and exploit searches).
- **Brute-force Attacks**: Performs dictionary-based attacks on SSH, FTP, RDP, and Telnet.
- **Vulnerability Mapping**: Uses **Nmap Vulners script** and **Searchsploit** for CVE lookups.
- **Custom Password List**: Allows users to select a password list from SecLists, provide their own, or generate one using **Crunch**.
- **Automated Report Generation**: Saves all scan results in a ZIP file.

## Prerequisites
Before running the script, ensure the following:
- You are using **Kali Linux**.
- You have **root privileges**.
- Required tools are installed (**Nmap, Hydra, Masscan, and Searchsploit**).

## Installation
Clone this repository and navigate into the directory:
```bash
 git clone https://github.com/yourusername/network-scan-script.git
 cd network-scan-script
```

## Usage
1. Grant execute permissions to the script:
```bash
chmod +x network_scan.sh
```
2. Run the script as **root**:
```bash
sudo ./network_scan.sh
```
3. Enter the **CIDR range** to scan.
4. Select the **scan type** (Basic or Full).
5. Choose a password list for brute-force attacks.

## Script Workflow
1. Checks for **root access**.
2. Prompts the user for **network range**.
3. Creates or selects the **output directory**.
4. Installs required tools if missing.
5. **Scans the network**:
   - Uses **Nmap** for TCP/UDP scans, service enumeration, and vulnerability detection.
   - Uses **Masscan** for high-speed port scanning.
6. **Performs brute-force attacks** on detected services (SSH, RDP, FTP, Telnet) using **Hydra** and **Medusa**.
7. **Searches for vulnerabilities** using **Nmap Vulners script** and **Searchsploit**.
8. **Displays and saves results** in a ZIP file.

## Output Files
The script stores scan results in the following structure:
- **network_scan_results/** → Main working directory
- **network_scan_results/Nmap_\<IP>.txt** → Nmap scan results per IP
- **network_scan_results/Masscan_\<IP>.txt** → Masscan scan results per IP
- **network_scan_results/medusa_ssh_\<IP>.txt** → SSH brute-force results
- **network_scan_results/medusa_rdp_\<IP>.txt** → RDP brute-force results
- **network_scan_results/medusa_ftp_\<IP>.txt** → FTP brute-force results
- **network_scan_results/medusa_telnet_\<IP>.txt** → Telnet brute-force results
- **network_scan_results/searchsploit_results_\<keyword>.txt** → ExploitDB search results
- **network_scan_results/password_lists/** → Stored password lists used for brute-force attacks
- **network_scan_results/results_scan.zip** → Compressed scan results archive

## Example Output
```
You are root.. continuing..
Please provide the network range in CIDR format (e.g., 192.168.1.0/24):
192.168.1.0/24
Creating output directory...
Installing required tools...
[ ✓ ] All required tools installed.
Scanning the network...
Nmap scan completed.
Masscan scan completed.
Performing brute-force attack on SSH...
Performing brute-force attack on FTP...
Performing brute-force attack on RDP...
Performing brute-force attack on Telnet...
Saving results...
Results successfully compressed into: network_scan_results/results_scan.zip
```

## Credits
- Created by **May Hazon**
- Lecturer: **Erel**
- Class Code: **S5**
- Unit: **TMagen773632**

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

