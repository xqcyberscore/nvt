# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1391.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123285");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:01:45 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1391");
script_tag(name: "insight", value: "ELSA-2014-1391 -  glibc security, bug fix, and enhancement update - [2.12-1.149] - Remove gconv transliteration loadable modules support (CVE-2014-5119, - _nl_find_locale: Improve handling of crafted locale names (CVE-2014-0475, [2.12-1.148] - Switch gettimeofday from INTUSE to libc_hidden_proto (#1099025). [2.12-1.147] - Fix stack overflow due to large AF_INET6 requests (CVE-2013-4458, #1111460). - Fix buffer overflow in readdir_r (CVE-2013-4237, #1111460). [2.12-1.146] - Fix memory order when reading libgcc handle (#905941). - Fix format specifier in malloc_info output (#1027261). - Fix nscd lookup for innetgr when netgroup has wildcards (#1054846). [2.12-1.145] - Add mmap usage to malloc_info output (#1027261). [2.12-1.144] - Use NSS_STATUS_TRYAGAIN to indicate insufficient buffer (#1087833). [2.12-1.143] - [ppc] Add VDSO IFUNC for gettimeofday (#1028285). - [ppc] Fix ftime gettimeofday internal call returning bogus data (#1099025). [2.12-1.142] - Also relocate in dependency order when doing symbol dependency testing (#1019916). [2.12-1.141] - Fix infinite loop in nscd when netgroup is empty (#1085273). - Provide correct buffer length to netgroup queries in nscd (#1074342). - Return NULL for wildcard values in getnetgrent from nscd (#1085289). - Avoid overlapping addresses to stpcpy calls in nscd (#1082379). - Initialize all of datahead structure in nscd (#1074353). [2.12-1.140] - Return EAI_AGAIN for AF_UNSPEC when herrno is TRY_AGAIN (#1044628). [2.12-1.139] - Do not fail if one of the two responses to AF_UNSPEC fails (#845218). [2.12-1.138] - nscd: Make SELinux checks dynamic (#1025933). [2.12-1.137] - Fix race in free() of fastbin chunk (#1027101). [2.12-1.136] - Fix copy relocations handling of unique objects (#1032628). [2.12-1.135] - Fix encoding name for IDN in getaddrinfo (#981942). [2.12-1.134] - Fix return code from getent netgroup when the netgroup is not found (#1039988). - Fix handling of static TLS in dlopen'ed objects (#995972). [2.12-1.133] - Don't use alloca in addgetnetgrentX (#1043557). - Adjust pointers to triplets in netgroup query data (#1043557)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1391");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1391.html");
script_cve_id("CVE-2013-4237","CVE-2013-4458");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
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
  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.12~1.149.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.12~1.149.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.12~1.149.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.12~1.149.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-static", rpm:"glibc-static~2.12~1.149.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.12~1.149.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.12~1.149.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

