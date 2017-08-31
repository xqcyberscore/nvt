# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1628.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123025");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 09:46:47 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1628");
script_tag(name: "insight", value: "ELSA-2015-1628 -  mysql55-mysql security update - [5.5.45-1]- Rebase to 5.5.45 Includes fixes for: CVE-2014-6568 CVE-2015-0374 CVE-2015-0381 CVE-2015-0382 CVE-2015-0391 CVE-2015-0411 CVE-2015-0432 CVE-2015-0501 CVE-2015-2568 CVE-2015-0499 CVE-2015-2571 CVE-2015-0433 CVE-2015-0441 CVE-2015-0505 CVE-2015-2573 CVE-2015-2582 CVE-2015-2620 CVE-2015-2643 CVE-2015-2648 CVE-2015-4737 CVE-2015-4752 CVE-2015-4757 Resolves: #1247020"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1628");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1628.html");
script_cve_id("CVE-2015-0433","CVE-2015-0441","CVE-2015-0499","CVE-2015-0501","CVE-2015-0505","CVE-2015-2568","CVE-2015-2571","CVE-2015-2573","CVE-2015-2582","CVE-2015-2620","CVE-2015-2643","CVE-2015-2648","CVE-2015-4737","CVE-2015-4752","CVE-2015-4757","CVE-2014-6568","CVE-2015-0374","CVE-2015-0381","CVE-2015-0382","CVE-2015-0391","CVE-2015-0411","CVE-2015-0432");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"mysql55-mysql", rpm:"mysql55-mysql~5.5.45~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mysql55-mysql-bench", rpm:"mysql55-mysql-bench~5.5.45~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mysql55-mysql-devel", rpm:"mysql55-mysql-devel~5.5.45~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mysql55-mysql-libs", rpm:"mysql55-mysql-libs~5.5.45~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mysql55-mysql-server", rpm:"mysql55-mysql-server~5.5.45~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"mysql55-mysql-test", rpm:"mysql55-mysql-test~5.5.45~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

