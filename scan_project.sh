#!bin/bash

# Student Name: May Hazon
# Class Code: S5
# Unit: TMagen773632
# Lecturer: Erel

# Define color variables
GREEN="\e[0;32m"
RED="\e[31m"
STOP="\e[0m"
BOLD="\e[1m"
CYAN="\e[0;36m"

HOME=$(pwd)

# Check if the user is root
function WHO_USER()
{
	user=$(whoami)
	echo -e "[ ! ] First Checking if you are root [ ! ]\n"
	sleep 1
	if [ "$user" == "root" ]
	then
		printf "${GREEN}"
		echo -e "You are root.. continuing..\n"
		printf "${STOP}"
	else
		printf "${RED}"
		echo -e "You are not root.. exiting...\n"
		printf "${STOP}"
		exit
	fi
}

# Function to handle user input for network range, output directory, and scan type
function USER_INPUT()
{
	local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
	while true 
	do
	echo -e "[ + ] Please provide me the network range you would like to scan in CIDR format (e.g., 192.168.1.0/24):\n"
	read range
	if [[ $range =~ $regex ]]
	then
		echo -e "\n${GREEN}[ ✓ ] Great! You provided a valid CIDR range: $range [ ✓ ]${STOP}\n"
		break
	else
		echo "No, this is not a valid CIDR format. Please try again."
	fi
	done
	while true
	do
	echo -e "Please provide me the output directory you want for the results\n"
	read dirr
	if [ -d "$dirr" ]
	then
		echo "Output directory exists: $dirr"
		break
	else
		echo -e "\nThe directory does not exist. Do you want to create it? (yes/no)"
		read response
		if [ "$response" == "yes" ]
            then
                mkdir -p "$dirr" && echo -e "\n${GREEN}[ ✓ ] Directory created: $dirr${STOP}\n"  
                break
        elif [ "$response" == "no" ] 
            then
                echo -e "[ ! ] You chose not to create the directory [ ! ]\n"
                ((attempts++))
                if (( attempts == max_attempts )) 
                then
                    echo -e "${RED}[ ❌ ] Maximum attempts reached. Exiting directory selection [ ❌ ]${STOP}\n"
                    exit 1
                else
                    echo -e "${CYAN}[ ! ] Please provide a valid directory [ ! ]${STOP}\n"
                fi
         fi
    fi
    done
    
	while true
	do
	echo -e "\n${BOLD}Nmap, Masscan and hydra required, The script will install them if needed!${STOP}\n"
	echo -e "${CYAN}Please choose scan type: 'Basic' or 'Full':${STOP}"
    read scan_type
    case $scan_type in
		Basic)
            echo -e "\nYou selected: Basic scan.\n"
            echo -e "${CYAN}${BOLD}The Basic scan includes TCP/UDP scans, service versions, and weak password checks.${STOP}\n"
            sleep 2
            break
            ;;
        Full)
            echo -e "\nYou selected: Full scan.\n"
            echo -e "${CYAN}${BOLD}The Full scan includes TCP/UDP scans, service versions, weak passwords, NSE scripts, and vulnerability mapping.${STOP}\n"
            sleep 2
            break
            ;;
        *)
            echo -e "${RED}Invalid choice. Please choose 'Basic' or 'Full'.${STOP}\n"
            ;;
    esac
    done
    nmap $range >> $dirr/range_ip.txt
    ip_list=$(cat $dirr/range_ip.txt | awk '/Nmap scan report/{print $NF}')
    vmware_ips=$(arp -a | grep '00:50:56' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
    my_ip=$(ifconfig | grep -w inet | awk '{print $2}')
    default_gw=$(route -n | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
    filtered_ip_list=$(echo "$ip_list" | grep -v -x -e "$my_ip" -e "$default_gw" -e "$vmware_ips")
    
    echo -e "${CYAN}The following IP addresses will be scanned:${STOP}"
	echo "$filtered_ip_list"
	echo -e "${CYAN}-----------------------------------------------${STOP}\n"
	for ip in $filtered_ip_list
	do
        if [[ "$scan_type" == "Basic" ]]; then
            BASIC_SCAN $ip
        elif [[ "$scan_type" == "Full" ]]; then
            FULL_SCAN $ip
        else
            echo -e "${RED}[ ❌ ] Invalid scan type. Exiting [ ❌ ]${STOP}\n"
            exit 1
        fi
    done
    SAVE_RESULTS
}

# Function to perform a basic scan
function BASIC_SCAN()
{
	BASIC_INSTALL
	echo -e "${BOLD}[ ! ] Starting Nmap scan for $ip, it might taking a few minutes... [ ! ]${STOP}\n"
	nmap $ip -p- -sV --script=ftp-brute.nse --min-rate=1000 >> $dirr/Nmap_$ip.txt
	echo -e "${GREEN}Nmap scan completed. Results saved to: $dirr/Nmap_$ip.txt${STOP}\n"
	echo -e "${BOLD}[ ! ] Starting masscan scan for $ip, it might take some time... [ ! ]${STOP}\n"
	sudo masscan -pU:1-65535 $ip --rate=1000 >> $dirr/Masscan_$ip.txt 2>&1
	echo -e "${GREEN}masscan scan completed. Results saved to: $dirr/Masscan_$ip.txt${STOP}\n"
	echo -e "Finish the scanning...\n"
	sleep 2
	PASSWORD_LIST_SELECTION
	DISPLAY_RESULTS
	SEARCH_RESULTS
}	

function BASIC_INSTALL()
{
		All_Packages=( "nmap" "hydra" "masscan" )
		for package in "${All_Packages[@]}"
		do
			dpkg -s "$package" >/dev/null 2>&1 || \
			sudo apt-get install "$package" -y >/dev/null 2>&1
		done
}

function FULL_INSTALL()
{
		All_Packages=( "nmap" "hydra" "masscan" "exploitdb" )
		for package in "${All_Packages[@]}"
		do
			dpkg -s "$package" >/dev/null 2>&1 || \
			sudo apt-get install "$package" -y >/dev/null 2>&1
		done
}

# Function to perform a full scan
function FULL_SCAN()
{
	FULL_INSTALL
	echo -e "${BOLD}[ ! ] Starting Nmap scan for $ip, it might taking a few minutes... [ ! ]${STOP}\n"
	nmap $ip -p- -sV -sC --script=vulners.nse --min-rate=1000 >> $dirr/Nmap_$ip.txt
	echo -e "${GREEN}Nmap scan and vulnerability completed. Results saved to: $dirr/Nmap_$ip.txt${STOP}\n"
	echo -e "${BOLD}[ ! ] Starting masscan scan for $ip, it might take some time... [ ! ]${STOP}\n"
	sudo masscan -pU:1-65535 $ip --rate=1000 >> $dirr/Masscan_$ip.txt 2>&1
	echo -e "${GREEN}masscan scan completed. Results saved to: $dirr/Masscan_$ip.txt${STOP}\n"
	echo -e "Finish the scanning...\n"
	PASSWORD_LIST_SELECTION
	SEARCH_SPLOIT
	DISPLAY_RESULTS
	SEARCH_RESULTS
}

# Function to show the nmap vulners results and use searchsploit
function SEARCH_SPLOIT()
{
	echo -e "\n${CYAN}Displaying vulnerability scan results.${STOP}\n"
	sleep 4
	cat "$dirr/Nmap_$ip.txt"
    while true 
    do
        echo -e "\n${CYAN}Do you have a protocol name, CVE, or word you want to search with searchsploit?${STOP}\n"
        read word_search

        if [[ -z "$word_search" ]]
        then
            echo -e "${RED}[ ! ] You didn't enter anything. Please try again[ ! ]${STOP}\n"
            continue
        fi

        output_file="searchsploit_results_$word_search.txt"
        echo -e "[ ✓ ] Searching for '$word_search' in searchsploit...\n"
        searchsploit "$word_search" | tee "$dirr/$output_file"
        sleep 2
        echo -e "\n${GREEN}Results saved to: $output_file${STOP}\n"

        echo -e "Do you want to search for another word? (yes/no)\n"
        read search_again

        if [[ "$search_again" != "yes" ]]
        then
            echo -e "\n${CYAN}Exiting searchsploit...${STOP}\n"
            break
        fi
    done
}

# Function to select or create a password list
function PASSWORD_LIST_SELECTION()
{
	sleep 1
	echo "---------------------------------"
    echo -e "${CYAN}Password List Selection${STOP}"
    echo "---------------------------------"
    echo -e "Please choose an option for the password list:\n"
    echo "1) Use SecLists Top 15 Passwords"
    echo "2) Provide your own password list"
    echo "3) Create a new password list (Using crunch)"
    
    echo -e "\nEnter your choice (1, 2, or 3): "
    read pass_choise
    
    case $pass_choise in
		1)
			git clone https://github.com/yarinmaimon1/Lists.git >/dev/null 2>&1
			cp ./Lists/best15SecListsPass.txt $dirr/best15SecListsPass.txt
			rm -rf Lists
			echo -e "\n${GREEN}Using SecLists Top 15 Passwords:${STOP}\n"
			password_file="$dirr/best15SecListsPass.txt"
			SSH_SCAN
			;;
		2)
			while true 
			do
                echo -e "\n${CYAN}Please provide the full path to your password list:${STOP}\n"
                read user_password_file
                if [[ -f "$user_password_file" ]]
                then
					password_file="$user_password_file"
                    echo -e "\n${GREEN}Using your provided password list: $password_file${STOP}\n"
                    SSH_SCAN
                    break
                else
                    echo -e "\n${RED}File not found. Please enter a valid file path.${STOP}"
                fi
            done
            ;;
         3)
			echo -e "\n${CYAN}Creating a new password list.${STOP}\n"
			echo -e "please provide the minimum length for the password\n"
			read min
			echo -e "please provide the maximum length for the password\n"
			read max
			echo -e "please provide the characters you want for the password\n"
			read char
			echo -e "Starting create for you password list...\n"
			crunch $min $max $char >> $dirr/crunch_list_$ip.txt
			password_file="$dirr/crunch_list_$ip.txt"
			echo -e "${GREEN}Created password list: $password_file.${STOP}\n"
			SSH_SCAN
			;;
		 *)
			echo -e "\n${RED}[ ! ]Invalid choice. Please select 1, 2, or 3.[ ! ]${STOP}\n"
			PASSWORD_LIST_SELECTION
			;;
		esac
}

# Function to brute force the ssh service and display the weak passwords
function SSH_SCAN()
{
	echo -e "${CYAN}Scanning for SSH weak passwords...${STOP}\n"
	sleep 2
	sshscan=$(cat $dirr/Nmap_$ip.txt | grep -i 'ssh' | grep 'open' | awk '{print $2}' | head -1)
	if [ "$sshscan" == "open" ]
	then
		echo -e "${CYAN}Starting brute force attack on SSH...${STOP}\n"
		medusa -h $ip -U $password_file -P $password_file -M ssh -f -t30 2>/dev/null | grep -i "found" >> "$dirr/medusa_ssh_$ip.txt"
		echo -e "${GREEN}SSH brute force results saved to: $dirr/medusa_ssh_$ip.txt${STOP}\n"
		sleep 1
	else
		echo -e "${RED}SSH service is closed.${STOP}\n"
	fi
	RDP_SCAN
}

# Function to brute force the rdp service and display the weak passwords
function RDP_SCAN()
{
	echo -e "${CYAN}Scanning for RDP weak passwords...${STOP}\n"
	sleep 2
	rdpscan=$(cat $dirr/Nmap_$ip.txt | grep -i '3389' | awk '{print $2}' | head -1)
	if [ "$rdpscan" == "open" ]
	then
		echo -e "${CYAN}Starting brute force attack on RDP...${STOP}\n"
		medusa -h $ip -U $password_file -P $password_file -M rdp -f -t30 2>/dev/null | grep -i "found" >> "$dirr/medusa_rdp_$ip.txt"
		echo -e "${GREEN}RDP brute force results saved to: $dirr/medusa_rdp_$ip.txt${STOP}\n"
		sleep 1
	else
		echo -e "${RED}RDP service is closed.${STOP}\n"
	fi
	FTP_SCAN
}

# Function to brute force the ftp service and display the weak passwords
function FTP_SCAN()
{
	echo -e "${CYAN}Scanning for FTP weak passwords...${STOP}\n"
	sleep 2
	ftpscan=$(cat $dirr/Nmap_$ip.txt | grep -i 'ftp' | grep 'open' | awk '{print $2}' | tail -1)
	if [ "$ftpscan" == "open" ]
	then
		echo -e "${CYAN}Starting brute force attack on FTP...${STOP}\n"
		medusa -h $ip -U $password_file -P $password_file -M ftp -f -t30 2>/dev/null | grep -i "found" >> "$dirr/medusa_ftp_$ip.txt"
		echo -e "${GREEN}FTP brute force results saved to: $dirr/medusa_ftp_$ip.txt${STOP}\n"
		sleep 1
	else
		echo -e "${RED}FTP service is closed.${STOP}\n"
	fi
	TELNET_SCAN
}

# Function to brute force the telnet service and display the weak passwords
function TELNET_SCAN()
{
	echo -e "${CYAN}Scanning for TELNET weak passwords...${STOP}\n"
	sleep 2
	telnetscan=$(cat $dirr/Nmap_$ip.txt | grep -i 'telnet' | grep 'open' | awk '{print $2}' | head -1)
	if [ "$telnetscan" == "open" ]
	then
		echo -e "${CYAN}Starting brute force attack on TELNET...${STOP}\n"
		medusa -h $ip -U $password_file -P $password_file -M telnet -f -t30 2>/dev/null | grep -i "found" >> "$dirr/medusa_telnet_$ip.txt"
		echo -e "${GREEN}FTP brute force results saved to: $dirr/medusa_telnet_$ip.txt${STOP}\n"
		sleep 1
	else
		echo -e "${RED}FTP service is closed.${STOP}\n"
	fi
}

#Asks the user if they want to search within the results
function DISPLAY_RESULTS() {
    echo -e "${BOLD}Do you want to:${STOP}\n"
    echo -e "1) Display all results"
    echo -e "2) See a list of result files and choose one to view"
    echo -e "Enter your choice (1 or 2):"
    read choice

    if [[ "$choice" == "1" ]]; then
        echo -e "\n${CYAN}Displaying all results:${STOP}\n"
        for file in "$dirr"/*
        do
            if [[ -s "$file" ]]; then
                sleep 1
                echo -e "${CYAN}Displaying contents of: $file${STOP}"
                echo -e "${CYAN}--------------------------------${STOP}"
                cat "$file"
                echo -e "${CYAN}--------------------------------${STOP}\n"
                sleep 2
            else
                echo ""
            fi
        done
    elif [[ "$choice" == "2" ]]; then
        echo -e "\n${CYAN}Here is the list of available result files:${STOP}\n"
        ls -1 "$dirr"
        while true; do
            echo -e "\n${CYAN}Enter the name of the file you want to view (or type 'exit' to quit):${STOP}"
            read file_name
            if [[ "$file_name" == "exit" ]]; then
                echo -e "Exiting file selection.\n"
                break
            elif [[ -s "$dirr/$file_name" ]]; then
                sleep 1
                echo -e "${CYAN}Displaying contents of: $file_name${STOP}"
                echo -e "${CYAN}--------------------------------${STOP}"
                cat "$dirr/$file_name"
                echo -e "\n${CYAN}--------------------------------${STOP}\n"
                break
            else
                echo "${RED}Invalid choice. Insert name of a file...${STOP}\n"
            fi
        done
    else
        echo -e "${RED}[ ❌ ] Invalid choice. Exiting...${STOP}\n"
    fi
}

# Function to search inside the results
function SEARCH_RESULTS()
{
	while true 
	do
        echo -e "${CYAN}Enter a keyword to search in the results (for example, 'SSH', 'CVE', 'HTTP') or press Enter to exit:${STOP}\n"
        read keyword
        echo ""
        if [[ -z "$keyword" ]]
        then
            echo -e "No keyword entered. Exiting search functionality.\n"
            break
        fi

        echo -e "${CYAN}Searching for '$keyword' in the results...${STOP}"
        for file in "$dirr"/*
        do
            if [[ "$file" != "$password_file" ]]
            then
                grep -i "$keyword" "$file" >> "$dirr/search_results_$keyword.txt"
            fi
        done   
        if [[ -s "$dirr/search_results_$keyword.txt" ]] 
        then
            echo -e "${GREEN}Found Results for '$keyword':${STOP}\n"
            cat "$dirr/search_results_$keyword.txt"
            echo -e "${GREEN}Saved in $dirr/search_results_$keyword.txt${STOP}\n"
        else
            echo -e "${RED}No results found for '$keyword'.${STOP}\n"
        fi

        echo -e "${CYAN}Do you want to search for another keyword? (yes/no):${STOP}"
        read search_key

        if [[ "$search_key" != "yes" ]]
        then
            echo -e "Exiting search functionality...\n"
            break
        fi
    done
}

# Function to save all results into a zip file
function SAVE_RESULTS()
{
	echo -e "Saving all results into a zip file...\n"
	cd "$HOME" && zip -r "results_scan.zip" $dirr >/dev/null 2>&1

	if [[ $? == 0 ]]
	then
		echo -e "${GREEN}${BOLD}[ + ] All results have been saved to: $HOME/results_scan.zip [ + ]${STOP}"
	else
		echo -e "${RED}[ ! ] Failed to save results into a zip file [ ! ]${STOP}\n"
	fi
}

WHO_USER
USER_INPUT
