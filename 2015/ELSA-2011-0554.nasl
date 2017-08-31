# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0554.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122171");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:14:13 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0554");
script_tag(name: "insight", value: "ELSA-2011-0554 -  python security, bug fix, and enhancement update - python:[2.6.6-20]Resolves: CVE-2010-3493[2.6.6-19]Resolves: CVE-2011-1015[2.6.6-18]Resolves: CVE-2011-1521[2.6.6-17]- recompile against systemtap 1.4Related: rhbz#569695[2.6.6-16]- recompile against systemtap 1.4Related: rhbz#569695[2.6.6-15]- fix race condition that sometimes breaks the build with parallel makeResolves: rhbz#690315[2.6.6-14]- backport pre-canned ways of salting a password to the 'crypt' moduleResolves: rhbz#681878[2.6.6-13]- move lib2to3/tests to the python-test subpackageRelated: rhbz#625395[2.6.6-12]- fix a new test in 2.6.6 that was failing on 64-bit big-endian architecturesResolves: rhbz#677392[2.6.6-11]- fix incompatibility between 2.6.6 and our non-standard M2Crypto.SSL.SSLTimeoutErrorResolves: rhbz#681811[2.6.6-10]- add workaround for bug in rhythmbox-0.12 exposed by python 2.6.6Resolves: rhbz#684991[2.6.6-9]- prevent tracebacks for the 'py-bt' gdb command on x86_64Resolves: rhbz#639392[2.6.6-8]- fix a regression in 2.6.6 relative to 2.6.5 in urllib2Resolves: rhbz#669847[2.6.6-7]- add an optional 'timeout' argument to the subprocess module (patch 131)Resolves: rhbz#567229[2.6.6-6]- prevent _sqlite3.so being built with a redundant RPATH of _libdir (patch 130)- remove DOS batch file 'idle.bat'- remove shebang lines from .py files that aren't executable, and removeexecutability from .py files that don't have a shebang lineRelated: rhbz#634944- add 'Obsoletes: python-ssl' to core package, as 2.6 contains the ssl moduleResolves: rhbz#529274[2.6.6-5]- allow the 'no_proxy' environment variable to override 'ftp_proxy' inurllib2 (patch 128)Resolves: rhbz#637895- make garbage-collection assertion failures more informative (patch 129)Resolves: rhbz#614680[2.6.6-4]- backport subprocess fixes to use the 'poll' system call, rather than 'select'Resolves: rhbz#650588[2.6.6-3]- use an ephemeral port for IDLE, enabling multiple instances to be runResolves: rhbz#639222- add systemtap static markers, tapsets, and example scriptsResolves: rhbz#569695[2.6.6-2]- fix dbm.release on ppc64/s390xResolves: rhbz#626756- fix missing lib2to3 test filesResolves: rhbz#625395- fix test.test_commands SELinux incompatibilityResolves: rhbz#625393- make 'pydoc -k' more robust in the face of broken modulesResolves: rhbz#603073[2.6.6-1]- rebase to 2.6.6: (which contains the big whitespace cleanup of r81031) http://www.python.org/download/releases/2.6.6/ - fixup patch 102, patch 11, patch 52, patch 110 - drop upstreamed patches: patch 113 (CVE-2010-1634), patch 114 (CVE-2010-2089), patch 115 (CVE-2008-5983), patch 116 (rhbz598564), patch 118 (rhbz540518) - add fix for upstream bug in test_posix.py introduced in 2.6.6 (patch 120)Resolves: rhbz#627301python-docs:[2.6.6-2]- rebuild[2.6.6-1]- rebase to 2.6.6 to track the main python packageRelated: rhbz#627301"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0554");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0554.html");
script_cve_id("CVE-2010-3493","CVE-2011-1015","CVE-2011-1521");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.6.6~20.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.6.6~20.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.6.6~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.6.6~20.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-test", rpm:"python-test~2.6.6~20.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.6.6~20.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.6.6~20.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

