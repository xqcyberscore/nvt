# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-2079.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122749");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-24 10:17:24 +0200 (Tue, 24 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-2079");
script_tag(name: "insight", value: "ELSA-2015-2079 -  binutils security, bug fix, and enhancement update - [2.23.52.0.1-55]- Add missing delta to patch that fixes parsing corrupted archives. (#1162666)[2.23.52.0.1-54]- Import patch for PR 18270: Create AArch64 GOT entries for local symbols. (#1238783)[2.23.52.0.1-51]- Fix incorrectly generated binaries and DSOs on PPC platforms. (#1247126)[2.23.52.0.1-50]- Fix memory corruption parsing corrupt archives. (#1162666)[2.23.52.0.1-49]- Fix directory traversal vulnerability. (#1162655)[2.23.52.0.1-48]- Fix stack overflow in SREC parser. (#1162621)[2.23.52.0.1-47]- Fix stack overflow whilst parsing a corrupt iHex file. (#1162607)[2.23.52.0.1-46]- Fix out of bounds memory accesses when parsing corrupt PE binaries. (#1162594, #1162570)[2.23.52.0.1-45]- Change strings program to default to -a. Fix problems parsing files containg corrupt ELF group sections. (#1157276)[2.23.52.0.1-44]- Avoid reading beyond function boundary when disassembling. (#1060282)- For binary ouput, we don't have an ELF bfd output so can't access elf_elfheader. (#1226864)[2.23.52.0.1-43]- Don't discard stap probe note sections on aarch64 (#1225091)[2.23.52.0.1-42]- Clamp maxpagesize at 1 (rather than 0) to avoid segfaults in the linker when passed a bogus max-page-size argument. (#1203449)[2.23.52.0.1-41]- Fixup bfd elf_link_add_object_symbols for ppc64 to prevent subsequent uninitialized accesses elsewhere. (#1172766)[2.23.52.0.1-40]- Minor testsuite adjustments for PPC changes in -38/-39. (#1183838) Fix md_assemble for PPC to handle arithmetic involving the TOC better. (#1183838)[2.23.52.0.1-39]- Fix ppc64: segv in libbfd (#1172766).[2.23.52.0.1-38]- Unconditionally apply ppc64le patches (#1183838).[2.23.52.0.1-37]- Andreas's backport of z13 and dependent fixes for s390, including tesetcase fix from Apr 27, 2015. (#1182153)[2.23.52.0.1-35]- Fixup testsuite for AArch64 (#1182111)- Add support for @localentry for LE PPC64 (#1194164)[2.23.52.0.1-34]- Do not install windmc(1) man page (#850832)[2.23.52.0.1-33]- Don't replace R_390_TLS_LE{32,64} with R_390_TLS_TPOFF for PIE (#872148)- Enable relro by default for arm and aarch64 (#1203449)- Backport 3 RELRO improvements for ppc64/ppc64le from upstream (#1175624)[2.23.52.0.1-31]- Backport upstream RELRO fixes. (#1200138)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-2079");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-2079.html");
script_cve_id("CVE-2014-8503","CVE-2014-8504","CVE-2014-8737","CVE-2014-8738","CVE-2014-8484","CVE-2014-8485","CVE-2014-8501","CVE-2014-8502");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"binutils", rpm:"binutils~2.23.52.0.1~55.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"binutils-devel", rpm:"binutils-devel~2.23.52.0.1~55.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

