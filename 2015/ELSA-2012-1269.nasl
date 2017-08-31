# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-1269.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123813");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:54 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-1269");
script_tag(name: "insight", value: "ELSA-2012-1269 -  qpid security, bug fix, and enhancement update - python-qpid[0.14-11]- BZs: 825078- Resolves: rhbz#840053qpid-cpp[0.14-22.0.1.el6_3 ]- Update summary and description in specfile to be product neutral[0.14-22]- BZs: 609685, 849654, 854004[0.14-21]- BZs: 831365, 840982, 844618[0.14-20]- BZs: 683711, 689408, 825078, 834608, 841196, 841488[0.14-19]- BZs: 609685, 683711, 693444, 707682, 729311, 801465, 808090, 809357, 811481, 817283, 826989, 831365, 835628[0.14-18]- BZs: 609685, 729311, 808090, 809357, 817283qpid-qmf[0.14-14.0.1.el6_3]- Change build vendor[0.14-14]- BZs: 693845, 773700, 806869, 847331qpid-tools[0.14-6]- Resolves: rhbz#840058- Fixed: Bug 850111 - qpid-stat -c mech column data missing"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-1269");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-1269.html");
script_cve_id("CVE-2012-2145");
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
  if ((res = isrpmvuln(pkg:"python-qpid", rpm:"python-qpid~0.14~11.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-qpid-qmf", rpm:"python-qpid-qmf~0.14~14.0.1.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qpid-cpp-client", rpm:"qpid-cpp-client~0.14~22.0.1.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qpid-cpp-client-ssl", rpm:"qpid-cpp-client-ssl~0.14~22.0.1.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qpid-cpp-server", rpm:"qpid-cpp-server~0.14~22.0.1.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qpid-cpp-server-ssl", rpm:"qpid-cpp-server-ssl~0.14~22.0.1.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qpid-qmf", rpm:"qpid-qmf~0.14~14.0.1.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"qpid-tools", rpm:"qpid-tools~0.14~6.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ruby-qpid-qmf", rpm:"ruby-qpid-qmf~0.14~14.0.1.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

