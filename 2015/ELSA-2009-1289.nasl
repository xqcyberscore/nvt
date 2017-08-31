# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-1289.nasl 6554 2017-07-06 11:53:20Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122444");
script_version("$Revision: 6554 $");
script_tag(name:"creation_date", value:"2015-10-08 14:45:29 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:53:20 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2009-1289");
script_tag(name: "insight", value: "ELSA-2009-1289 -  mysql security and bug fix update - [5.0.77-3]- Add fix for CVE-2009-2446 (format string vulnerability in COM_CREATE_DB and COM_DROP_DB processing)Resolves: #512200[5.0.77-2]- Back-port upstream fix for CVE-2008-4456 (mysql command line client XSS flaw)Resolves: #502169[5.0.77-1]- Update to MySQL 5.0.77, for numerous fixes described at http://dev.mysql.com/doc/refman/5.0/en/releasenotes-cs-5-0-77.html including low-priority security issues CVE-2008-2079, CVE-2008-3963Resolves: #448487, #448534, #452824, #453156, #455619, #456875Resolves: #457218, #462534, #470036, #476896, #479615- Improve mysql.init to pass configured datadir to mysql_install_db, and to force user=mysql for both mysql_install_db and mysqld_safe.Resolves: #450178- Fix mysql.init to wait correctly when socket is not in default placeResolves: #435494"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-1289");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-1289.html");
script_cve_id("CVE-2008-2079","CVE-2008-3963","CVE-2008-4456","CVE-2009-2446");
script_tag(name:"cvss_base", value:"8.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.0.77~3.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.0.77~3.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.0.77~3.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.0.77~3.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.0.77~3.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

