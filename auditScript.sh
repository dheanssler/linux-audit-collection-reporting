#!/bin/bash
####CONFIGURATION####
hostsSSH="./hostsSSH"
hostsRSH="./hostsRSH"
outputDir="/tmp/otherInfo"

###ENDOFCONFIGURATION###

###FUNCTIONS###
printBanner () {
	myvar="$1"
	result="\n=========================================\n=========================================\n$myvar\n=========================================\n=========================================\n\n"
	printf "$result"
}

###ENDOFFUNCTIONS###
<<com
#Collect information via SSH
for host in $(cat $hostsSSH); do
	scp -q ./collectOtherInfo.sh $host:/root/collectOtherInfo.sh
	ssh -t $host "chmod +x /root/collectOtherInfo.sh ; /root/collectOtherInfo.sh"
	hostname=$(echo $host | awk -F "." '{print $1}') #included to extract the hostname from a FQDN
	if [ ! -d /var/log/remotelogs/$hostname/otherInfo/ ]; then
		mkdir -p /var/log/remotelogs/$hostname/otherInfo/
	fi
	scp -q $host:/tmp/otherInfo/* /var/log/remotelogs/$hostname/otherInfo/
	ssh -t $host "rm -f /tmp/otherInfo/*; rm /root/collectOtherInfo.sh"
done

#Collect information via RSH
for host in $(cat $hostsRSH); do
	rcp ./collectOtherInfo.sh $host:/tmp/collectOtherInfo.sh
	rsh $host "/tmp/collectOtherInfo.sh 2>/dev/null"
	hostname=$(echo $host | awk -F "." '{print $1}') #included to extract the hostname from a FQDN
	if [ ! -d /var/log/remotelogs/$hostname/otherInfo/ ]; then
		mkdir -p /var/log/remotelogs/$hostname/otherInfo/
	fi
	rcp $host:/tmp/otherInfo/* /var/log/remotelogs/$hostname/otherInfo/
	rsh $host "rm -f /tmp/otherInfo/*; rm /tmp/collectOtherInfo.sh"
done

#Filter out specific lines from Audit Reports
for host in $(cat $hostsSSH $hostsRSH); do
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
for host in $(cat $hostsSSH $hostsRSH); do
	hostname=$(echo $host | awk -F "." '{print $1}') #included to extract the hostname from a FQDN
	logwatch --detail high --numeric --range all --hostlimit $hostname --logdir /var/log/remotelogs/$hostname > /var/log/remotelogs/$hostname/otherInfo/$hostname"_logwatch"`date +%Y%m%d`
done


com
#Compile reports

for host in $(cat $hostsSSH $hostsRSH); do
	hostname=$(echo $host | awk -F "." '{print $1}') #included to extract the hostname from a FQDN
	if [ ! -d /var/log/completedReports/$hostname ]; then
		mkdir -p /var/log/completedReports/$hostname/
	fi
	printBanner "$hostname" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "Report Generated On: "`date +%Y%m%d`"\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printBanner "Logwatch Report" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	#cat /var/log/remotelogs/$hostname/otherInfo/$hostname"_logwatch"`date +%Y%m%d` >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
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
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Passsword Aging (Chage) Commands" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nUsage of the 'chage' command. The 'chage' command is used to change or view user password expiry information.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the parameter passed to the command is not '-l'. These events may indicate that the password aging information for an account was manually changed. All accounts are required to have their password changed at least once every ninety (90) days.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "File and Directory Attribute and Permission Changes" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, lremovexattr, chown, fchown, fchownat, lchown, chmod, fchmod, or fchmodat system calls. Successful/unsuccessful uses of the chcon, setfacl, or chacl commands.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the changes are being applied to security relevant objects and the changes are not being made by  a system administrator or cybersecurity team member. \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "Password Changes" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\nSuccessful/unsuccessful uses of the passwd command. The 'passwd' command is used to change passwords for user accounts.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\nEvents where the auid does not belong to a system administrator and the subject of the command is a service account, group account, or backup local administrator account. Events where the auid does not match the subject of the command  and the auid does not belong to a system administrator.\n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	###
	printBanner "" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What is included?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	printf "What should I look for?\n \n\n" >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	cat /var/log/remotelogs/$hostname/otherInfo/auditReport_identity >> /var/log/completedReports/$hostname/$hostname"_Report_"`date +%Y%m%d`
	
done

#printBanner "TESTING 123"

<<com
ausearch -k identity | aureport -i -f  >> $outputDir"/auditReport_identity"
ausearch -k privileged-priv_change | aureport -i -u >> $outputDir"/auditReport_privileged-priv_change"
ausearch -k privileged-chage | aureport -i -u >> $outputDir"/auditReport_privileged-chage"
ausearch -k perm_mod | aureport -i --comm --summary >> $outputDir"/auditReport_perm_mod"
ausearch -k perm_mod | aureport -i -x --summary >> $outputDir"/auditReport_perm_mod"
ausearch -k perm_mod | aureport -i -f >> $outputDir"/auditReport_perm_mod"
ausearch -k privileged-passwd | aureport -i -u --summary >> $outputDir"/auditReport_privileged-passwd"
ausearch -k privileged-passwd | aureport -i --comm >> $outputDir"/auditReport_privileged-passwd"
ausearch -k privileged-mount | aureport -i -u --summary >> $outputDir"/auditReport_privileged-mount"
ausearch -k privileged-mount | aureport -i --comm >> $outputDir"/auditReport_privileged-mount"
ausearch -k privileged-unix-update | aureport -i -u --summary >> $outputDir"/auditReport_privileged-unix-update"
ausearch -k privileged-unix-update | aureport -i --comm >> $outputDir"/auditReport_privileged-unix-update"
ausearch -k privileged-pam_timestamp_check | aureport -i -u --summary >> $outputDir"/auditReport_privileged-pam_timestamp_check"
ausearch -k privileged-pam_timestamp_check | aureport -i --comm >> $outputDir"/auditReport_privileged-pam_timestamp_check"
ausearch -k priv_cmd | aureport -i -u --summary >> $outputDir"/auditReport_priv_cmd"
ausearch -k priv_cmd | aureport -i --comm >> $outputDir"/auditReport_priv_cmd"
ausearch -k privileged-gpasswd | aureport -i -u --summary >> $outputDir"/auditReport_privileged-gpasswd"
ausearch -k privileged-gpasswd | aureport -i --comm >> $outputDir"/auditReport_privileged-gpasswd"
ausearch -k module_chng | aureport -i -u --summary >> $outputDir"/auditReport_module_chng"
ausearch -k module_chng | aureport -i --comm >> $outputDir"/auditReport_module_chng"
ausearch -k privileged-crontab | aureport -i -u --summary >> $outputDir"/auditReport_privileged-crontab"
ausearch -k privileged-crontab | aureport -i --comm >> $outputDir"/auditReport_privileged-crontab"
ausearch -k privileged-usermod | aureport -i -u --summary >> $outputDir"/auditReport_privileged-usermod"
ausearch -k privileged-usermod | aureport -i --comm >> $outputDir"/auditReport_privileged-usermod"
ausearch -k logins | aureport -i -f >> $outputDir"/auditReport_logins"
ausearch -k execpriv | aureport -i -u --summary >> $outputDir"/auditReport_execpriv"
ausearch -k execpriv | aureport -i --comm --summary >> $outputDir"/auditReport_execpriv"
ausearch -k execpriv | aureport -i --comm >> $outputDir"/auditReport_execpriv"
ausearch -k privileged-ssh | aureport -i -u --summary >> $outputDir"/auditReport_privileged-ssh"
ausearch -k privileged-ssh | aureport -i --comm >> $outputDir"/auditReport_privileged-ssh"
ausearch -k delete | aureport -i --comm --summary >> $outputDir"/auditReport_delete"
ausearch -k delete | aureport -i -f >> $outputDir"/auditReport_delete"
ausearch -k perm_access | aureport -i -u --summary >> $outputDir"/auditReport_perm_access"
ausearch -k perm_access | aureport -i --comm >> $outputDir"/auditReport_perm_access"
ausearch -k modules | aureport -i -u --summary >> $outputDir"/auditReport_modules"
ausearch -k modules | aureport -i --comm >> $outputDir"/auditReport_modules"
ausearch -k audit-tools | aureport -i -f >> $outputDir"/auditReport_audit-tools"
ausearch -k security-relevant-object | aureport -i -u --summary >> $outputDir"/auditReport_security-relevant-object"
ausearch -k encryption_management | aureport -i -u --summary >> $outputDir"/auditReport_encryption_management"
ausearch -k encryption_management | aureport -i --comm >> $outputDir"/auditReport_encryption_management"



com