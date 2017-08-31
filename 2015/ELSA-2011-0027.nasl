# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0027.nasl 6600 2017-07-07 09:58:31Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122278");
script_version("$Revision: 6600 $");
script_tag(name:"creation_date", value:"2015-10-06 14:15:51 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-07 11:58:31 +0200 (Fri, 07 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0027");
script_tag(name: "insight", value: "ELSA-2011-0027 -  python security, bug fix, and enhancement update - [2.4.3-43]- add missing patch 206Related: rhbz#549372[2.4.3-42]- fix test_pyclbr to match the urllib change in patch 204 (patch 206)- allow the 'no_proxy' environment variable to override 'ftp_proxy' inurllib2 (patch 207)- fix typos in names of patches 204 and 205Related: rhbz#549372[2.4.3-41]- backport support for the 'no_proxy' environment variable to the urllib andurllib2 modules (patches 204 and 205, respectively)Resolves: rhbz#549372[2.4.3-40]- backport fixes for arena allocator from 2.5a1- disable arena allocator when run under valgrind on x86, x86_64, ppc, ppc64(patch 203)- add patch to add sys._debugmallocstats() hook (patch 202)Resolves: rhbz#569093[2.4.3-39]- fix various flaws in the 'audioop' module- Resolves: CVE-2010-1634 CVE-2010-2089- backport the new PySys_SetArgvEx libpython entrypoint from 2.6- Related: CVE-2008-5983- restrict creation of the .relocation-tag files to i386 builds- Related: rhbz#644761- move the python-optik metadata from the core subpackage to the python-libssubpackage- Related: rhbz#625372[2.4.3-38]- add metadata to ensure that 'yum install python-libs' works- Related: rhbz#625372[2.4.3-37]- create dummy ELF file '.relocation-tag' to force RPM directory coloring,fixing i386 on ia64 compat- Resolves: rhbz#644761[2.4.3-36]- Backport fix for http://bugs.python.org/issue7082 to 2.4.3- Resolves: rhbz#644147[2.4.3-35]- Rework rgbimgmodule fix for CVE-2008-3143- Resolves: rhbz#644425 CVE-2009-4134 CVE-2010-1449 CVE-2010-1450[2.4.3-34]- fix stray 'touch' command- Related: rhbz#625372[2.4.3-33]- Preserve timestamps when fixing shebangs (patch 104) and when installing, tominimize .pyc/.pyo differences across architectures (due to the embedded mtimein .pyc/.pyo headers)- Related: rhbz#625372[2.4.3-32]- introduce libs subpackage as a dependency of the core package, moving theshared libraries and python standard libraries there- Resolves: rhbz#625372[2.4.3-31]- dont use -b when applying patch 103- Related: rhbz#263401[2.4.3-30]- add missing patch- Resolves: rhbz#263401[2.4.3-29]- Backport Python 2.5s tarfile module (0.8.0) to 2.4.3- Resolves: rhbz#263401[2.4.3-28]- Backport fix for leaking filedescriptors in subprocess error-handling pathfrom Python 2.6- Resolves: rhbz#609017- Backport usage of 'poll' within the subprocess module to 2.4.3- Resolves: rhbz#609020"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0027");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0027.html");
script_cve_id("CVE-2008-5983","CVE-2009-4134","CVE-2010-1449","CVE-2010-1450","CVE-2010-1634","CVE-2010-2089");
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
  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.4.3~43.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.4.3~43.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-libs", rpm:"python-libs~2.4.3~43.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.4.3~43.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.4.3~43.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

