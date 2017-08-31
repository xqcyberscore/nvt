# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0791.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122163");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:14:06 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0791");
script_tag(name: "insight", value: "ELSA-2011-0791 -  tomcat6 security and bug fix update - [6.0.24-33]- resolves: rhbz 695284 - multiple instances logging fiasco[6.0.24-32]- Resolves: rhbz 698624 - inet4address can't be cast to String[6.0.24-31]- Resolves: rhbz 656403 - cve-2010-4172 jsp syntax error[6.0.24-30]- Resolves: rhbz#697504 initscript logging location[6.0.24-29]- Resolves: rhbz#656403, rhbz#675926, rhbz#676011- CVE-2010-4172, CVE-2010-3718, CVE-2011-0013, CVE-2010-4476,- CVE-2011-0534[6.0.24-28]- Resovles rhbz#695284 - wrapper logs to different locations- CVE-2010-4172, CVE-2011-0013, CVE-2010-3718 commented out - until needed.[6.0.24-27]- naming-factory-dbcp missing fix in tomcat6.conf- Add Obsoletes for log4j[6.0.24-26]- Add log4j to package lib. Corrected typo in log4 Provides- epock versus epoch[6.0.24-25]- Installed permissions do not allow tomcat to start- incrementing NVR so yum won't get confused with the zstream"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0791");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0791.html");
script_cve_id("CVE-2010-3718","CVE-2010-4172","CVE-2011-0013");
script_tag(name:"cvss_base", value:"4.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
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
  if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.24~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tomcat6-admin-webapps", rpm:"tomcat6-admin-webapps~6.0.24~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tomcat6-docs-webapp", rpm:"tomcat6-docs-webapp~6.0.24~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tomcat6-el", rpm:"tomcat6-el~2.1~api~6.0.24~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tomcat6-javadoc", rpm:"tomcat6-javadoc~6.0.24~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tomcat6-jsp", rpm:"tomcat6-jsp~2.1~api~6.0.24~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.24~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tomcat6-servlet", rpm:"tomcat6-servlet~2.5~api~6.0.24~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tomcat6-webapps", rpm:"tomcat6-webapps~6.0.24~33.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

