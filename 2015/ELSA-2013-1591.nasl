# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1591.nasl 9335 2018-04-05 13:50:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123517");
script_version("$Revision: 9335 $");
script_tag(name:"creation_date", value:"2015-10-06 14:04:56 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2018-04-05 15:50:33 +0200 (Thu, 05 Apr 2018) $");
script_name("Oracle Linux Local Check: ELSA-2013-1591");
script_tag(name: "insight", value: "ELSA-2013-1591 -  openssh security, bug fix, and enhancement update - [5.3p1-94]- use dracut-fips package to determine if a FIPS module is installed (#1001565)[5.3p1-93]- use dist tag in suffixes for hmac checksum files (#1001565)[5.3p1-92]- use hmac_suffix for ssh{,d} hmac checksums (#1001565)[5.3p1-91]- fix NSS keys support (#1004763)[5.3p1-90]- change default value of MaxStartups - CVE-2010-5107 - #908707- add -fips subpackages that contains the FIPS module files (#1001565)[5.3p1-89]- don't use SSH_FP_MD5 for fingerprints in FIPS mode (#998835)[5.3p1-88]- do ssh_gssapi_krb5_storecreds() twice - before and after pam session (#974096)[5.3p1-87]- bump the minimum value of SSH_USE_STRONG_RNG to 14 according to SP800-131A (#993577)- fixed an issue with broken 'ssh -I pkcs11' (#908038)- abort non-subsystem sessions to forced internal sftp-server (#993509)- reverted 'store krb5 credentials after a pam session is created (#974096)'[5.3p1-86]- Add support for certificate key types for users and hosts (#906872)- Apply RFC3454 stringprep to banners when possible (#955792)[5.3p1-85]- fix chroot logging issue (#872169)- change the bad key permissions error message (#880575)- fix a race condition in ssh-agent (#896561)- backport support for PKCS11 from openssh-5.4p1 (#908038)- add a KexAlgorithms knob to the client and server configuration (#951704)- fix parsing logic of ldap.conf file (#954094)- Add HMAC-SHA2 algorithm support (#969565)- store krb5 credentials after a pam session is created (#974096)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1591");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1591.html");
script_cve_id("CVE-2010-5107");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"openssh", rpm:"openssh~5.3p1~94.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-askpass", rpm:"openssh-askpass~5.3p1~94.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-clients", rpm:"openssh-clients~5.3p1~94.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-ldap", rpm:"openssh-ldap~5.3p1~94.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openssh-server", rpm:"openssh-server~5.3p1~94.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"pam_ssh_agent_auth", rpm:"pam_ssh_agent_auth~0.9.3~94.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

