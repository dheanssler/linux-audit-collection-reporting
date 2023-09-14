#!/bin/bash
####CONFIGURATION####
hostsSSH="./hostsSSH"
hostsRSH="./hostsRSH"
outputDir="/tmp/otherInfo"
issoGroup="sa"
exec 2>/dev/null

###ENDOFCONFIGURATION###

###FUNCTIONS###
printBanner () {
	myvar="$1"
	result="\n=========================================\n=========================================\n$myvar\n=========================================\n=========================================\n\n"
	printf "$result"
}

###ENDOFFUNCTIONS###

#Cleanup old files
printf "" > ./hostsSSH.failed
printf "" > ./hostsRSH.failed
printf "" > ./aliveHosts

#Collect information via SSH
#printf "Starting SSH connections...\n"
for host in $(cat $hostsSSH); do
	getent hosts $host &> /dev/null
	result=$?
	if [ $result -eq 0 ]; then
		echo "aaaa" > /dev/tcp/$host/22 2>&1 >/dev/null
		result=$?
		if [ $result -eq 0 ]; then
			scp -q ./collectOtherInfo.sh $host:/root/collectOtherInfo.sh 2>/dev/null
			result=$?
			if [ $result -eq 0 ]; then
				ssh -q -t $host "chmod +x /root/collectOtherInfo.sh ; /root/collectOtherInfo.sh 2>/dev/null" 2>/dev/null
				hostname=$(echo $host | awk -F "." '{print $1}') #included to extract the hostname from a FQDN
				if [ ! -d /var/log/remotelogs/$hostname/otherInfo/ ]; then
					mkdir -p /var/log/remotelogs/$hostname/otherInfo/
				fi
				scp -q $host:/tmp/otherInfo/* /var/log/remotelogs/$hostname/otherInfo/ 2>/dev/null
				ssh -q -t $host "rm -f /tmp/otherInfo/*; rm /root/collectOtherInfo.sh" 2>/dev/null
			else
				printf "$host: Unable to authenticate to SSH server.\n"
				printf "$host\n" >> ./hostsSSH.failed
			fi
		else
			printf "$host: Unable to connect to SSH server on standard port 22/tcp.\n"
			printf "$host\n" >> ./hostsSSH.failed
		fi
	else
		printf "$host: Unable to resolve hostname.\n"
		printf "$host\n" >> ./hostsSSH.failed
	fi
done
#printf "SSH connections finished.\n"

#Collect information via RSH
#printf "Starting RSH connections...\n"
for host in $(cat $hostsRSH); do
	getent hosts $host &> /dev/null
	result=$?
	if [ $result -eq 0 ]; then
		echo "aaaa" > /dev/tcp/$host/514 &>/dev/null
		result=$?
		if [ $result -eq 0 ]; then
			rcp ./collectOtherInfo.sh $host:/root/collectOtherInfo.sh 2>/dev/null
			result=$?
			if [ $result -eq 0 ]; then
				rsh $host "chmod +x /root/collectOtherInfo.sh ; /root/collectOtherInfo.sh 2>/dev/null" 2>/dev/null
				hostname=$(echo $host | awk -F "." '{print $1}') #included to extract the hostname from a FQDN
				if [ ! -d /var/log/remotelogs/$hostname/otherInfo/ ]; then
					mkdir -p /var/log/remotelogs/$hostname/otherInfo/
				fi
				rcp $host:/tmp/otherInfo/* /var/log/remotelogs/$hostname/otherInfo/ 2>/dev/null
				rsh $host "rm -f /tmp/otherInfo/*; rm /root/collectOtherInfo.sh" 2>/dev/null
			else
				printf "$host: Unable to authenticate to RSH server.\n"
				printf "$host\n" >> ./hostsRSH.failed
			fi
		else
			printf "$host: Unable to connect to rsh server on standard port 514/tcp.\n"
			printf "$host\n" >> ./hostsRSH.failed
		fi
	else
		printf "$host: Unable to resolve hostname.\n"
		printf "$host\n" >> ./hostsRSH.failed
	fi
done
#printf "RSH connections finished.\n"

#Filter out failed hosts
cat $hostsSSH $hostsRSH | grep -v "$(cat hostsSSH.failed hostsRSH.failed)" > ./aliveHosts
if [ ! -s ./aliveHosts ]; then
	printf "No host data gathered. Skipping report generation.\n"
	exit 1
fi


#Filter out specific lines from Audit Reports
for host in $(cat ./aliveHosts); do
	hostname=$(echo $host | awk -F "." '{print $1}') #included to extract the hostname from a FQDN
	date +%Y%m%d >> /var/log/remotelogs/$hostname/otherInfo/removedFromReports
	for i in $(ls -d /var/log/remotelogs/$hostname/otherInfo/auditReport_*); do
		grep -E "auditctl\s+\(none\)\s+\?\s+unset\s+[0-9]{1,3}$" $i >> /var/log/remotelogs/$hostname/otherInfo/removedFromReports
		sed -i -E '/auditctl\s+\(none\)\s+\?\s+unset\s+[0-9]{1,3}$/d' $i
		grep -E "sendto\s+yes\s+\/usr\/sbin\/auditctl\s+unset\s+[0-9]{1,3}$" $i >> /var/log/remotelogs/$hostname/otherInfo/removedFromReports
		sed -i -E '/sendto\s+yes\s+\/usr\/sbin\/auditctl\s+unset\s+[0-9]{1,3}$/d' $i
		grep -E "unset\s+\(none\)\s+\?\s+\/usr\/sbin\/auditctl\s+[0-9]{1,3}$" $i >> /var/log/remotelogs/$hostname/otherInfo/removedFromReports
		sed -i -E '/unset\s+\(none\)\s+\?\s+\/usr\/sbin\/auditctl\s+[0-9]{1,3}$/d' $i
	done
done

#Generate Logwatch Reports
printf "Generating logwatch report(s) for $(cat ./aliveHosts | wc -l) host(s)...\n"
for host in $(cat ./aliveHosts); do
	hostname=$(echo $host | awk -F "." '{print $1}') #included to extract the hostname from a FQDN
	logwatch --detail high --numeric --range all --hostlimit $hostname --logdir /var/log/remotelogs/$hostname > /var/log/remotelogs/$hostname/otherInfo/$hostname"_logwatch"`date +%Y%m%d`
done

#Compile reports
printf "Generating final report(s) for $(cat ./aliveHosts | wc -l) host(s)...\n"
for host in $(cat ./aliveHosts); do
	hostname=$(echo $host | awk -F "." '{print $1}') #included to extract the hostname from a FQDN
	if [ ! -d /var/log/completedReports/$hostname ]; then
		mkdir -p /var/log/completedReports/$hostname/
	fi
	printBanner "$hostname" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "Report Generated On: "`date +%Y%m%d`"\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printBanner "Logwatch Report" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/$hostname"_logwatch"`date +%Y%m%d` >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Auditd Section" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "User Identity" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nAccount creations, modifications, disabling, and termination events that affect /etc/shadow, /etc/security/opasswd, /etc/passwd, /etc/gshadow, /etc/group, /etc/sudoers,  or /etc/sudoers.d/.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator or cybersecurity team member.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Switch User (SU) Commands" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nUsage of the switch user (su) command. The 'su' command allows a user to run commands with a substitute user and group ID.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator or cybersecurity team member. Events where the account switched to is another user account that does not belong to the user running the SU command.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_privileged-priv_change >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "\n=FULL CONTEXT BELOW=\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditFull_privileged-priv_change >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Passsword Aging (Chage) Commands" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nUsage of the 'chage' command. The 'chage' command is used to change or view user password expiry information.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the parameter passed to the command is not '-l'. These events may indicate that the password aging information for an account was manually changed. All accounts are required to have their password changed at least once every ninety (90) days.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_privileged-chage >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "\n=FULL CONTEXT BELOW=\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditFull_privileged-chage >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "File and Directory Attribute and Permission Changes" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, lremovexattr, chown, fchown, fchownat, lchown, chmod, fchmod, or fchmodat system calls. Successful/unsuccessful uses of the chcon, setfacl, or chacl commands.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the changes are being applied to security relevant objects and the changes are not being made by  a system administrator or cybersecurity team member. \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_perm_mod >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Password Changes" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the passwd command. The 'passwd' command is used to change passwords for user accounts.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator and the subject of the command is a service account, group account, or backup local administrator account. Events where the auid does not match the subject of the command  and the auid does not belong to a system administrator.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_privileged-passwd >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "\n=FULL CONTEXT BELOW=\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditFull_privileged-passwd >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "File System Mounting and Unmounting" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the mount or umount command. Successful/unsuccessful uses of the mount syscall.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_privileged-mount >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Unix Updates" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the unix_update, postdrop, postqueue, semanage, setfiles, userhelper, setsebool, or unix_chkpasswd commands.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_privileged-unix-update >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "PAM Timestamp Check" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the pam_timestamp_check command. The 'pam_timestamp_check' command is used to check if the default timestamp is valid.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_privileged-pam_timestamp_check >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Privileged Commands" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the newgrp, chsh, or sudo commands. The 'newgrp' command is used to change the current group ID during a login session. The 'chsh' command is used to change the login shell. The 'sudo' command allows a permitted user to execute a command as the superuser or another user, as specified by the security policy.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator and the auid is not authorized to access the subject of the command.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_priv_cmd >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "\n=FULL CONTEXT BELOW=\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditFull_priv_cmd >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Group Management" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the gpasswd command. The 'gpasswd' command is used to administer /etc/group and /etc/gshadow. Every group can have administrators, members and a password.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_privileged-gpasswd >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Kernel Module Management" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the init_module or finit_module system calls. The 'init_module' and 'finit_module' system calls are used to load a kernel module. Successful/unsuccessful uses of the delete_module system call. The 'delete_module' system call is used to unload a kernel module.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator. Events where the module being loaded is a restricted or prohibited module.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_module_chng >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "\n=FULL CONTEXT BELOW=\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditFull_module_chng >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Crontab Management" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the crontab command. The 'crontab' command is used to maintain crontab files for individual users. Crontab is the program used to install, remove, or list the tables used to drive the cron daemon. This is similar to the task scheduler used in other operating systems.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_privileged-crontab >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "User Account Modifications" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the usermod command.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator or cybersecurity team member.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_privileged-usermod >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Logins" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful modifications to the faillock or lastlog log file.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents that occur outside of normal business hours.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_logins >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Execution of Privileged Commands" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nThe execution of privileged functions and software executing at higher privilege levels than users executing the software.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the command run (comm) is either unknown or should not be run by that user.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_execpriv >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Privileged SSH Commands" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the ssh-agent or ssh-keysign commands. The 'ssh-agent' is a program to hold private keys used for public key authentication. The 'ssh-keysign' program is an SSH helper program for host-based authentication.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator or cybersecurity team member.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_privileged-ssh >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Object Deletions" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the rename, unlink, rmdir, renameat, or unlinkat system calls.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the command run (comm) is unknown. Events where the auid should not be deleting the file.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_delete >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Permissions and Access Failures" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the truncate, ftruncate, creat, open, openat, and open_by_handle_at system calls. The 'creat' system call is used to open and possibly create a file or device. The 'open' system call opens a file specified by a pathname. If the specified file does not exist, it may optionally be created by 'open'. The 'openat' system call opens a file specified by a relative pathname. The 'name_to_handle_at' and 'open_by_handle_at' system calls split the functionality of 'openat' into two parts: 'name_to_handle_at' returns an opaque handle that corresponds to a specified file; 'open_by_handle_at' opens the file corresponding to a handle returned by a previous call to 'name_to_handle_at' and returns an open file descriptor.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator or cybersecurity team member.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_perm_access >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Additional Kernel Module Management" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the kmod command.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator or cybersecurity team member. Events where the module being loaded is a restricted or prohibited module.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_modules >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Modification of Audit Binaries" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful attempts to modify binaries related to the audit function.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_audit-tools >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Modification of Security Relevant Objects" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful attempts to modify security relevant objects.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator or cybersecurity team member.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_security-relevant-object >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Encryption Management" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful attempts to view or modify cryptographic key information for data at rest mechanisms.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator or cybersecurity team member.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_encryption_management >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
done

#Set Permissions
chown -R root:$issoGroup /var/log/completedReports
chown -R root:$issoGroup /var/log/remotelogs
find /var/log/completedReports -type d -exec chmod 0750 {} +
find /var/log/remotelogs -type d -exec chmod 0750 {} +
find /var/log/completedReports -type f -exec chmod 0640 {} +
find /var/log/remotelogs -type f -exec chmod 0640 {} +