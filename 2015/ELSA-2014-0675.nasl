# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0675.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123377");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:02:59 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0675");
script_tag(name: "insight", value: "ELSA-2014-0675 -  java-1.7.0-openjdk security update - [1.7.0.55-2.4.7.2.0.1.el7_0]- Update DISTRO_NAME in specfile[1.7.0.55-2.4.7.2]- Remove NSS patches. Issues with PKCS11 provider mean it shouldn't be enabled.- Always setup nss.cfg and depend on nss-devel at build-time to do so.- This allows users who wish to use PKCS11+NSS to just add it to java.security.- Patches to PKCS11 provider will be included upstream in 2.4.8 (ETA July 2014)- Resolves: rhbz#1099565[1.7.0.55-2.4.7.0.el7]- bumped to future icedtea-forest 2.4.7- updatever set to 55, buildver se to 13, release reset to 0- removed upstreamed patch402 gstackbounds.patch- removed Requires: rhino, BuildRequires is enough- ppc64 repalced by power64 macro- patch111 applied as dry-run (6.6 forward port)- nss enabled, but notused as default (6.6 forward port)- Resolves: rhbz#1099565"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0675");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0675.html");
script_cve_id("CVE-2014-0454","CVE-2014-0455","CVE-2014-0456","CVE-2014-0457","CVE-2014-0458","CVE-2014-0459","CVE-2014-0460","CVE-2014-0461","CVE-2014-1876","CVE-2014-2397","CVE-2014-2398","CVE-2014-2402","CVE-2014-2403","CVE-2014-2412","CVE-2014-2413","CVE-2014-2414","CVE-2014-2421","CVE-2014-2423","CVE-2014-2427","CVE-2014-0429","CVE-2014-0446","CVE-2014-0451","CVE-2014-0452","CVE-2014-0453");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.55~2.4.7.2.0.1.el7_0", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-accessibility", rpm:"java-1.7.0-openjdk-accessibility~1.7.0.55~2.4.7.2.0.1.el7_0", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.55~2.4.7.2.0.1.el7_0", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.55~2.4.7.2.0.1.el7_0", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-headless", rpm:"java-1.7.0-openjdk-headless~1.7.0.55~2.4.7.2.0.1.el7_0", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.55~2.4.7.2.0.1.el7_0", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.55~2.4.7.2.0.1.el7_0", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

