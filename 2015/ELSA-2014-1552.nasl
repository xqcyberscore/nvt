# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1552.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123284");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:01:44 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1552");
script_tag(name: "insight", value: "ELSA-2014-1552 -  openssh security, bug fix, and enhancement update - [5.3p1-104]- ignore SIGXFSZ in postauth monitor child (#1133906)[5.3p1-103]- don't try to generate DSA keys in the init script in FIPS mode (#1118735)[5.3p1-102]- ignore SIGPIPE in ssh-keyscan (#1108836)[5.3p1-101]- ssh-add: fix fatal exit when removing card (#1042519)[5.3p1-100]- fix race in backported ControlPersist patch (#953088)[5.3p1-99.2]- skip requesting smartcard PIN when removing keys from agent (#1042519)[5.3p1-98]- add possibility to autocreate only RSA key into initscript (#1111568)- fix several issues reported by coverity[5.3p1-97]- x11 forwarding - be less restrictive when can't bind to one of available addresses (#1027197)- better fork error detection in audit patch (#1028643)- fix openssh-5.3p1-x11.patch for non-linux platforms (#1100913)[5.3p1-96]- prevent a server from skipping SSHFP lookup (#1081338) CVE-2014-2653- ignore environment variables with embedded '=' or '\0' characters CVE-2014-2532- backport ControlPersist option (#953088)- log when a client requests an interactive session and only sftp is allowed (#997377)- don't try to load RSA1 host key in FIPS mode (#1009959)- restore Linux oom_adj setting when handling SIGHUP to maintain behaviour over restart (#1010429)- ssh-keygen -V - relative-specified certificate expiry time should be relative to current time (#1022459)[5.3p1-95]- adjust the key echange DH groups and ssh-keygen according to SP800-131A (#993580)- log failed integrity test if /etc/system-fips exists (#1020803)- backport ECDSA and ECDH support (#1028335)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1552");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1552.html");
script_cve_id("CVE-2014-2532","CVE-2014-2653");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~5.3p1~104.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~5.3p1~104.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~5.3p1~104.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-ldap", rpm:"openssh-ldap~5.3p1~104.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~5.3p1~104.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pam_ssh_agent_auth", rpm:"pam_ssh_agent_auth~0.9.3~104.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

