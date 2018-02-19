# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0973.nasl 8842 2018-02-16 09:52:40Z asteins $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123876");
script_version("$Revision: 8842 $");
script_tag(name:"creation_date", value:"2015-10-06 14:09:44 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2018-02-16 10:52:40 +0100 (Fri, 16 Feb 2018) $");
script_name("Oracle Linux Local Check: ELSA-2012-0973");
script_tag(name: "insight", value: "ELSA-2012-0973 -  nss, nss-util, and nspr security, bug fix, and enhancement update - nspr[4.9-1]- Resolves: rhbz#799193 - Update to 4.9nss[3.13.3-6.0.1.el6]- Added nss-vendor.patch to change vendor- Use blank image instead of clean.gif in tar ball[3.13.3-6]- Resolves: #rhbz#805232 PEM module may attempt to free uninitialized pointer[3.13.3-5]- Resolves: rhbz#717913 - [PEM] various flaws detected by Coverity- Require nss-util 3.13.3[3.13.3-4]- Resolves: rhbz#772628 nss_Init leaks memory[3.13.3-3]- Resolves: rhbz#746632 - pem_CreateObject mem leak on non existing file name- Use completed patch per code review[3.13.3-2]- Resolves: rhbz#746632 - pem_CreateObject mem leak on non existing file name- Resolves: rhbz#768669 - PEM unregistered callback causes SIGSEGV[3.13.3-1]- Update to 3.13.3- Resolves: rhbz#798539 - Distrust MITM subCAs issued by TrustWave- Remove builtins-nssckbi_1_88_rtm.patch which the rebase obsoletesnss-util[3.13.3-2]- Resolves: rhbz#799192 - Update to 3.13.3- Update minimum nspr version for Requires and BuildRequires to 4.9- Fix version/release in changelog to match the Version and Release tags, now 3.13.3-2[3.13.1-5]- Resolves: rhbz#799192 - Update to 3.13.3"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0973");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0973.html");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.9~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.9~1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss", rpm:"nss~3.13.3~6.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.13.3~6.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.13.3~6.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.13.3~6.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.13.3~6.0.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.13.3~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.13.3~2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

