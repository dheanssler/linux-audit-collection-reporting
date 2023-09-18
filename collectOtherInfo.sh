#!/bin/bash
####SETTINGS####
outputDir="/tmp/otherInfo"
PATH=$PATH:/usr/sbin

#Check if $outputDir exists and if not, create it and its parent directory
if [ ! -d $outputDir ]; then
	mkdir -p $outputDir
fi

#Clear out $outputDir before generating new files.
rm -rf /tmp/otherInfo/*

########
w >> $outputDir"/loggedOnUsers"

########
grep 'authentication failure' /var/log/messages | grep -v "grep 'authentication failure'" >> $outputDir"/failedLogins"
printf "\n"  >> $outputDir"failedLogins"
grep -e 'authentication failure' -e 'FAILED LOGIN' -e 'Failed password' -e deny /var/log/secure | grep -v "grep -e authentication" >> $outputDir"/failedLogins"
printf "\n"  >> $outputDir"failedLogins"
lastb  >> $outputDir"failedLogins"

########
last | grep -v -e'root\s*cron' >> $outputDir"/logins"

########
grep '(su)' /var/log/messages >> $outputDir"/authLogins"

########
grep -e 'su(' -e 'su\[' -e 'su:' -e 'sudo:' /var/log/secure | grep -v grep | grep -v 'user news' >> $outputDir"/suLogins"

########
grep -i -e 'password changed' -e 'password not' /var/log/secure >> $outputDir"/passwdChanges"

########
grep 'Interface ' /var/log/messages | grep -v grep >> $outputDir"/networkActivity"

########
grep -i 'server administrator' /var/log/messages >> $outputDir"/saProblems"

########
grep -i 'pam_tally' /var/log/secure | grep -v grep >> $outputDir"/denialOfSystem"


sa -a >> $outputDir"/acctSummary"
sa -cm >> $outputDir"/acctSummary"


ac -p >> $outputDir"/acctDetail"


#cat /var/log/messages >> $outputDir"/messages" #CAPTURED BY RSYSLOG


dmesg -c >> $outputDir"/errorLogger"


ausearch -i -k identity  >> $outputDir"/auditFull_identity"
ausearch -i -k privileged-priv_change  >> $outputDir"/auditFull_privileged-priv_change"
ausearch -i -k privileged-chage  >> $outputDir"/auditFull_privileged-chage"
ausearch -i -k perm_mod  >> $outputDir"/auditFull_perm_mod"
ausearch -i -k privileged-passwd  >> $outputDir"/auditFull_privileged-passwd"
ausearch -i -k privileged-mount  >> $outputDir"/auditFull_privileged-mount"
ausearch -i -k privileged-unix-update  >> $outputDir"/auditFull_privileged-unix-update"
ausearch -i -k privileged-pam_timestamp_check  >> $outputDir"/auditFull_privileged-pam_timestamp_check"
ausearch -i -k priv_cmd  >> $outputDir"/auditFull_priv_cmd"
ausearch -i -k privileged-gpasswd  >> $outputDir"/auditFull_privileged-gpasswd"
ausearch -i -k module_chng  >> $outputDir"/auditFull_module_chng"
ausearch -i -k privileged-crontab  >> $outputDir"/auditFull_privileged-crontab"
ausearch -i -k privileged-usermod  >> $outputDir"/auditFull_privileged-usermod"
ausearch -i -k logins  >> $outputDir"/auditFull_logins"
ausearch -i -k execpriv  >> $outputDir"/auditFull_execpriv"
ausearch -i -k privileged-ssh  >> $outputDir"/auditFull_privileged-ssh"
ausearch -i -k delete  >> $outputDir"/auditFull_delete"
ausearch -i -k perm_access  >> $outputDir"/auditFull_perm_access"
ausearch -i -k modules  >> $outputDir"/auditFull_modules"
ausearch -i -k audit-tools  >> $outputDir"/auditFull_audit-tools"
ausearch -i -k security-relevant-object  >> $outputDir"/auditFull_security-relevant-object"
ausearch -i -k encryption_management  >> $outputDir"/auditFull_encryption_management"

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