# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1605.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123527");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:05:05 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1605");
script_tag(name: "insight", value: "ELSA-2013-1605 -  glibc security, bug fix, and enhancement update - [2.12-1.132] - Revert the addition of gettimeofday vDSO function for ppc and ppc64 until OPD VDSO function call issues are resolved (#1026533). [2.12-1.131] - Call gethostbyname4_r only for PF_UNSPEC (#1022022). [2.12-1.130] - Fix integer overflows in *valloc and memalign. (#1008310). [2.12-1.129] - Initialize res_hconf in nscd (#970090). [2.12-1.128] - Update previous patch for dcigettext.c and loadmsgcat.c (#834386). [2.12-1.127] - Save search paths before performing relro protection (#988931). [2.12-1.126] - Correctly name the 240-bit slow path sytemtap probe slowpow_p10 for slowpow (#905575). [2.12-1.125] - Align value of stacksize in nptl-init (#663641). [2.12-1.124] - Renamed release engineering directory from 'fedora' to `releng' (#903754). [2.12-1.123] - Backport GLIBC sched_getcpu and gettimeofday vDSO functions for ppc (#929302). - Fall back to local DNS if resolv.conf does not define nameservers (#928318). - Add systemtap probes to slowexp and slowpow (#905575). [2.12-1.122] - Fix getaddrinfo stack overflow resulting in application crash (CVE-2013-1914, #951213). - Fix multibyte character processing crash in regexp (CVE-2013-0242, #951213). [2.12-1.121] - Add netgroup cache support for nscd (#629823). [2.12-1.120] - Fix multiple nss_compat initgroups() bugs (#966778). - Don't use simple lookup for AF_INET when AI_CANONNAME is set (#863384). [2.12-1.119] - Add MAP_HUGETLB and MAP_STACK support (#916986). - Update translation for stale file handle error (#970776). [2.12-1.118] - Improve performance of _SC_NPROCESSORS_ONLN (#rh952422). - Fix up _init in pt-initfini to accept arguments (#663641). [2.12-1.117] - Set reasonable limits on xdr requests to prevent memory leaks (#848748). [2.12-1.116] - Fix mutex locking for PI mutexes on spurious wake-ups on pthread condvars (#552960). - New environment variable GLIBC_PTHREAD_STACKSIZE to set thread stack size (#663641). [2.12-1.115] - Improved handling of recursive calls in backtrace (#868808). [2.12-1.114] - The ttyname and ttyname_r functions on Linux now fall back to searching for the tty file descriptor in /dev/pts or /dev if /proc is not available. This allows creation of chroots without the procfs mounted on /proc. (#851470) [2.12-1.113] - Don't free rpath strings allocated during startup until after ld.so is re-relocated. (#862094) [2.12-1.112] - Consistantly MANGLE/DEMANGLE function pointers. Fix use after free in dcigettext.c (#834386). [2.12-1.111] - Change rounding mode only when necessary (#966775). [2.12-1.110] - Backport of code to allow incremental loading of library list (#886968). [2.12-1.109] - Fix loading of audit libraries when TLS is in use (#919562) [2.12-1.108] - Fix application of SIMD FP exception mask (#929388)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1605");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1605.html");
script_cve_id("CVE-2013-0242","CVE-2013-1914","CVE-2013-4332");
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
  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.12~1.132.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.12~1.132.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.12~1.132.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.12~1.132.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.12~1.132.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.12~1.132.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.12~1.132.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

