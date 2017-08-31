# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1526.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122033");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:11:58 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-1526");
script_tag(name: "insight", value: "ELSA-2011-1526 -  glibc security, bug fix, and enhancement update - [2.12-1.47]- Don't start AVC thread until credentials are installed (#700507)[2.12-1.46]- Update systemtaparches[2.12-1.45]- Update configure script[2.12-1.44]- Add gdb hooks (#711927)[2.12-1.43]- Don't assume AT_PAGESIZE is always available (#739184)- Define IP_MULTICAST_ALL (#738763)[2.12-1.42]- Avoid race between {,__de}allocate_stack and __reclaim_stacks during fork (#738665)[2.12-1.41]- Locale-independent parsing in libintl (#737778)[2.12-1.40]- Change setgroups to affect all the threads in the process (#736346)[2.12-1.39]- Make sure AVC thread has capabilities (#700507)- Fix memory leak in dlopen with RTLD_NOLOAD (#699724)[2.12-1.38]- Build libresolv with stack protector (#730379)[2.12-1.37]- Maintain stack alignment when cancelling threads (#731042)[2.12-1.36]- Fix missing debuginfo (#729036)[2.12-1.35]- Report write error in addmnt even for cached streams (#688980, CVE-2011-1089)- Handle Lustre filesystem (#712248)[2.12-1.34]- Query NIS domain only when needed (#718057)- Update: Use mmap for allocation of buffers used for __abort_msg (#676591)[2.12-1.33]- Don't use gethostbyaddr to determine canonical name (#714823)[2.12-1.32]- ldd: never run file directly (#713134)[2.12-1.31]- Support Intel processor model 6 and model 0x2c (#695595)- Optimize memcpy for SSSE3 (#695812)- Optimize strlen for SSE2 (#695963)[2.12-1.30]- Support f_flags in Linux statfs implementation (#711987)[2.12-1.29]- Avoid overriding CFLAGS (#706903)[2.12-1.28]- Use mmap for allocation of buffers used for __abort_msg (#676591)[2.12-1.27]- Fix PLT use due to __libc_alloca_cutoff- Schedule nscd cache pruning more accurately from re-added values (#703481)- Fix POWER4 optimized strncmp to not read past differing bytes (#694386)[2.12-1.26]- Create debuginfo-common on biarch platforms (#676467)- Use Rupee sign in Indian locales (#692838)- Signal temporary host lookup errors in nscd as such to the requester (#703480)- Define initgroups callback for nss_files (#705465)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1526");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1526.html");
script_cve_id("CVE-2009-5064","CVE-2011-1089");
script_tag(name:"cvss_base", value:"6.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.12~1.47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.12~1.47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.12~1.47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.12~1.47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.12~1.47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.12~1.47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.12~1.47.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

