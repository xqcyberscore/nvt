# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2101.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122760");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:32 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2101");
script_tag(name: "insight", value: "ELSA-2015-2101 -  python security, bug fix, and enhancement update - [2.7.5-34.0.1]- Add Oracle Linux distribution in platform.py [orabug 20812544][2.7.5-34]- Revert fix for rhbz#1117751 as it leads to regressionsResolves: rhbz#1117751[2.7.5-33]- Only restore SIG_PIPE when Popen called with restore_sigpipeResolves: rhbz#1117751[2.7.5-32]- Backport SSLSocket.version function- Temporary disable test_gdb on ppc64le rhbz#1260558Resolves: rhbz#1259421[2.7.5-31]- Update load_cert_chain function to accept None keyfileResolves: rhbz#1250611[2.7.5-30]- Change Patch224 according to latest update in PEP493Resolves:rhbz#1219108[2.7.5-29]- Popen shouldn't ignore SIG_PIPEResolves: rhbz#1117751[2.7.5-28]- Exclude python subprocess temp files from cleaningResolves: rhbz#1058482[2.7.5-27]- Add list for cprofile sort optionResolves:rhbz#1237107[2.7.5-26]- Add switch to toggle cert verification on or off globallyResolves:rhbz#1219108[2.7.5-25]- PEP476 enable cert verifications by defaultResolves:rhbz#1219110[2.7.5-24]- Massive backport of ssl module from python3 aka PEP466Resolves: rhbz#1111461[2.7.5-23]- Fixed CVE-2013-1753, CVE-2013-1752, CVE-2014-4616, CVE-2014-4650, CVE-2014-7185Resolves: rhbz#1206574[2.7.5-22]- Fix importing readline producing erroneous outputResolves: rhbz#1189301[2.7.5-21]- Add missing import in bdist_rpmResolves: rhbz#1177613[2.7.5-20]- Avoid double close of subprocess pipesResolves: rhbz#1103452[2.7.5-19]- make multiprocessing ignore EINTRResolves: rhbz#1181624"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2101");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2101.html");
script_cve_id("CVE-2013-1753","CVE-2014-4616","CVE-2013-1752","CVE-2014-4650","CVE-2014-7185");
script_tag(name:"cvss_base", value:"6.4");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
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
  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.7.5~34.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-debug", rpm:"python-debug~2.7.5~34.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.5~34.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.7.5~34.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-test", rpm:"python-test~2.7.5~34.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.7.5~34.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.7.5~34.0.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

