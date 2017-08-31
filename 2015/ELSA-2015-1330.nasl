# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1330.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123066");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:58:55 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1330");
script_tag(name: "insight", value: "ELSA-2015-1330 -  python security, bug fix, and enhancement update - [2.6.6-64.0.1]- Add Oracle Linux distribution in platform.py [orabug 21288328] (Keshav Sharma)[2.6.6-64]- Enable use of deepcopy() with instance methodsResolves: rhbz#1223037[2.6.6-63]- Since -libs now provide python-ordered dict, added ordereddict dist-info to site-packagesResolves: rhbz#1199997[2.6.6-62]- Fix CVE-2014-7185/4650/1912 CVE-2013-1752Resolves: rhbz#1206572[2.6.6-61]- Fix logging module error when multiprocessing module is not initializedResolves: rhbz#1204966[2.6.6-60]- Add provides for python-ordereddictResolves: rhbz#1199997[2.6.6-59]- Let ConfigParse handle options without values- Add check phase to specfile, fix and skip relevant failing testsResolves: rhbz#1031709[2.6.6-58]- Make Popen.communicate catch EINTR errorResolves: rhbz#1073165[2.6.6-57]- Add choices for sort option of cProfile for better outputResolves: rhbz#1160640[2.6.6-56]- Make multiprocessing ignore EINTRResolves: rhbz#1180864[2.6.6-55]- Fix iteration over files with very long linesResolves: rhbz#794632[2.6.6-54]- Fix subprocess.Popen.communicate() being broken by SIGCHLD handler.Resolves: rhbz#1065537- Rebuild against latest valgrind-devel.Resolves: rhbz#1142170[2.6.6-53]- Bump release up to ensure proper upgrade path.Related: rhbz#958256"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1330");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1330.html");
script_cve_id("CVE-2013-1752","CVE-2014-1912","CVE-2014-4650","CVE-2014-7185");
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
  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.6.6~64.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.6.6~64.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.6.6~64.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-test", rpm:"python-test~2.6.6~64.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.6.6~64.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.6.6~64.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

