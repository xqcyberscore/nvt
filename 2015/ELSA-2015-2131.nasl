# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2131.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122741");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:18 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2131");
script_tag(name: "insight", value: "ELSA-2015-2131 -  openldap security, bug fix, and enhancement update - [2.4.40-8]- NSS does not support string ordering (#1231522)- implement and correct order of parsing attributes (#1231522)- add multi_mask and multi_strength to correctly handle sets of attributes (#1231522)- add new cipher suites and correct AES-GCM attributes (#1245279)- correct DEFAULT ciphers handling to exclude eNULL cipher suites (#1245279)[2.4.40-7]- Merge two MozNSS cipher suite definition patches into one. (#1245279)- Use what NSS considers default for DEFAULT cipher string. (#1245279)- Remove unnecesary defaults from ciphers' definitions (#1245279)[2.4.40-6]- fix: OpenLDAP shared library destructor triggers memory leaks in NSPR (#1249977)[2.4.40-5]- enhancement: support TLS 1.1 and later (#1231522,#1160467)- fix: openldap ciphersuite parsing code handles masks incorrectly (#1231522)- fix the patch in commit da1b5c (fix: OpenLDAP crash in NSS shutdown handling) (#1231228)[2.4.40-4]- fix: rpm -V complains (#1230263) -- make the previous fix do what was intended[2.4.40-3]- fix: rpm -V complains (#1230263)[2.4.40-2]- fix: missing frontend database indexing (#1226600)[2.4.40-1]- new upstream release (#1147982)- fix: PIE and RELRO check (#1092562)- fix: slaptest doesn't convert perlModuleConfig lines (#1184585)- fix: OpenLDAP crash in NSS shutdown handling (#1158005)- fix: slapd.service may fail to start if binding to NIC ip (#1198781)- fix: deadlock during SSL_ForceHandshake when getting connection to replica (#1125152)- improve check_password (#1174723, #1196243)- provide an unversioned symlink to check_password.so.1.1 (#1174634)- add findutils to requires (#1209229)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2131");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2131.html");
script_cve_id("CVE-2015-3276");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
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
  if ((res = isrpmvuln(pkg:"openldap", rpm:"openldap~2.4.40~8.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openldap-clients", rpm:"openldap-clients~2.4.40~8.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openldap-devel", rpm:"openldap-devel~2.4.40~8.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openldap-servers", rpm:"openldap-servers~2.4.40~8.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"openldap-servers-sql", rpm:"openldap-servers-sql~2.4.40~8.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

