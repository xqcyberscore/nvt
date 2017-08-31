# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0306.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123967");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:10:57 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0306");
script_tag(name: "insight", value: "ELSA-2012-0306 -  krb5 security and bug fix update - [1.6.1-70.el5]- add upstream patch for telnetd buffer overflow (CVE-2011-4862, #770351)[1.6.1-69.el5]- ftp: fix a static analysis should-never-happen NULL dereference (#750823)[1.6.1-68.el5]- backport fixes to teach libkrb5 to use descriptors higher than FD_SETSIZE to talk to a KDC by using poll() if it's detected at compile-time, revised (#701444, RT#6905)[1.6.1-67.el5]- add backported patch by way of jbarbuc to free subkeys created by the KDC while processing TGS requests (#708516)[1.6.1-66.el5]- add backported patch by way of several people to better avoid false detection of replay attacks when talking to systems with coarse time resolution (#713500)[1.6.1-65.el5]- ftpd: add backported patch to check for errors when calling setegid (MITKRB5-SA-2011-005, CVE-2011-1526, #719098)[1.6.1-64.el5]- klist: don't trip over referral entries when invoked with -s (#729067, RT#6915)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0306");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0306.html");
script_cve_id("CVE-2011-1526");
script_tag(name:"cvss_base", value:"6.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.1~70.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.6.1~70.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.1~70.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-server-ldap", rpm:"krb5-server-ldap~1.6.1~70.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.1~70.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

