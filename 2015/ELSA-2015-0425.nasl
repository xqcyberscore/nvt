# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-0425.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.123172");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 14:00:17 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-0425");
script_tag(name: "insight", value: "ELSA-2015-0425 -  openssh security, bug fix and enhancement update - [6.6.1p1-11 + 0.9.3-9]- fix direction in CRYPTO_SESSION audit message (#1171248)[6.6.1p1-10 + 0.9.3-9]- add new option GSSAPIEnablek5users and disable using ~/.k5users by default CVE-2014-9278 (#1169843)[6.6.1p1-9 + 0.9.3-9]- log via monitor in chroots without /dev/log (#1083482)[6.6.1p1-8 + 0.9.3-9]- increase size of AUDIT_LOG_SIZE to 256 (#1171163)- record pfs= field in CRYPTO_SESSION audit event (#1171248)[6.6.1p1-7 + 0.9.3-9]- fix gsskex patch to correctly handle MONITOR_REQ_GSSSIGN request (#1118005)[6.6.1p1-6 + 0.9.3-9]- correct the calculation of bytes for authctxt->krb5_ccname (#1161073)[6.6.1p1-5 + 0.9.3-9]- change audit trail for unknown users (#1158521)[6.6.1p1-4 + 0.9.3-9]- revert the default of KerberosUseKuserok back to yes- fix kuserok patch which checked for the existence of .k5login unconditionally and hence prevented other mechanisms to be used properly[6.6.1p1-3 + 0.9.3-9]- fix parsing empty options in sshd_conf- ignore SIGXFSZ in postauth monitor[6.6.1p1-2 + 0.9.3-9]- slightly change systemd units logic - use sshd-keygen.service (#1066615)- log when a client requests an interactive session and only sftp is allowed (#1130198)- sshd-keygen - don't generate DSA and ED25519 host keys in FIPS mode (#1143867)[6.6.1p1-1 + 0.9.3-9]- new upstream release (#1059667)- prevent a server from skipping SSHFP lookup - CVE-2014-2653 (#1081338)- make /etc/ssh/moduli file public (#1134448)- test existence of /etc/ssh/ssh_host_ecdsa_key in sshd-keygen.service- don't clean up gssapi credentials by default (#1134447)- ssh-agent - try CLOCK_BOOTTIME with fallback (#1134449)- disable the curve25519 KEX when speaking to OpenSSH 6.5 or 6.6- add support for ED25519 keys to sshd-keygen and sshd.sysconfig- standardise on NI_MAXHOST for gethostname() string lengths (#1097665)- set a client's address right after a connection is set (mindrot#2257) (#912792)- apply RFC3454 stringprep to banners when possible (mindrot#2058) (#1104662)- don't consider a partial success as a failure (mindrot#2270) (#1112972)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-0425");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-0425.html");
script_cve_id("CVE-2014-2653","CVE-2014-9278");
script_tag(name:"cvss_base", value:"5.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~6.6.1p1~11.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~6.6.1p1~11.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~6.6.1p1~11.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-keycat", rpm:"openssh-keycat~6.6.1p1~11.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-ldap", rpm:"openssh-ldap~6.6.1p1~11.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~6.6.1p1~11.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-server-sysvinit", rpm:"openssh-server-sysvinit~6.6.1p1~11.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pam_ssh_agent_auth", rpm:"pam_ssh_agent_auth~0.9.3~9.11.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

