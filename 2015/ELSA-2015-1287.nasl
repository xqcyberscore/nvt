# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1287.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123067");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:58:56 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1287");
script_tag(name: "insight", value: "ELSA-2015-1287 -  freeradius security, bug fix, and enhancement update - [2.2.6-4]- Move OpenSSL init out of version check Resolves: Bug#1189394 radiusd segfaults after update- Comment-out ippool-dhcp.conf inclusion Resolves: Bug#1189386 radiusd fails to start after 'clean' installation[2.2.6-3]- Disable OpenSSL version check Resolves: Bug#1189011[2.2.6-2]- Fix a number of new Coverity errors and compiler warnings. Resolves: Bug#1188598[2.2.6-1]- Upgrade to the latest upstream release v2.2.6 Resolves: Bug#921563 raddebug not working correctly Resolves: Bug#921567 raddebug -t 0 exists immediately Resolves: Bug#1060319 MSCHAP Authentication is not working using automatic windows user credentials Resolves: Bug#1078736 Rebase FreeRADIUS to 2.2.4 Resolves: Bug#1135439 Default message digest defaults to sha1 Resolves: Bug#1142669 EAP-TLS and OCSP validation causing segmentation fault Resolves: Bug#1173388 dictionary.mikrotik missing Attributes- Remove radutmp rotation Resolves: Bug#904578 radutmp should not rotate- Check for start_servers not exceeding max_servers Resolves: Bug#1146828 radiusd silently fails when start_servers is higher than max_servers"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1287");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1287.html");
script_cve_id("CVE-2014-2015");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"freeradius", rpm:"freeradius~2.2.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freeradius-krb5", rpm:"freeradius-krb5~2.2.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freeradius-ldap", rpm:"freeradius-ldap~2.2.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freeradius-mysql", rpm:"freeradius-mysql~2.2.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freeradius-perl", rpm:"freeradius-perl~2.2.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freeradius-postgresql", rpm:"freeradius-postgresql~2.2.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freeradius-python", rpm:"freeradius-python~2.2.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freeradius-unixODBC", rpm:"freeradius-unixODBC~2.2.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"freeradius-utils", rpm:"freeradius-utils~2.2.6~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

