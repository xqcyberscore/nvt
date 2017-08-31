# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0957.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123607");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:11 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0957");
script_tag(name: "insight", value: "ELSA-2013-0957 -  java-1.7.0-openjdk security update - [1.7.0.25-2.3.10.3.0.1.el6_4]- Update DISTRO_NAME in specfile[1.7.0.25-2.3.10.3.el6]- removed upstreamed patch1000 MBeanFix.patch- updated to newer IcedTea7-forest 2.3.10 with 8010118 fix- Resolves: rhbz#973119[1.7.0.25-2.3.10.2.el6]- added patch1000 MBeanFix.patch to fix regressions caused by security patches- Resolves: rhbz#973119[1.7.0.25-2.3.10.1.el6]- build bumped to 25- Resolves: rhbz#973119[1.7.0.19-2.3.10.0.el6]- Updated to latest IcedTea7-forest 2.3.10- patch 107 renamed to 500 for cosmetic purposes- improved handling of patch111 - nss-config-2.patch- removed patch 117, java-1.7.0-openjdk-nss-multiplePKCS11libraryInitialisationNnonCritical.patch duplicated with patch 108 (java-1.7.0-openjdk-nss-icedtea-e9c857dcb964)- Added client/server directories so they can be owned- Added fix for RH857717, owned /etc/.java/ and /etc/.java/.systemPrefs- Resolves: rhbz#973119"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0957");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0957.html");
script_cve_id("CVE-2013-1500","CVE-2013-1571","CVE-2013-2407","CVE-2013-2412","CVE-2013-2443","CVE-2013-2444","CVE-2013-2445","CVE-2013-2446","CVE-2013-2447","CVE-2013-2448","CVE-2013-2449","CVE-2013-2450","CVE-2013-2452","CVE-2013-2453","CVE-2013-2454","CVE-2013-2455","CVE-2013-2456","CVE-2013-2457","CVE-2013-2458","CVE-2013-2459","CVE-2013-2460","CVE-2013-2461","CVE-2013-2463","CVE-2013-2465","CVE-2013-2469","CVE-2013-2470","CVE-2013-2471","CVE-2013-2472","CVE-2013-2473");
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
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.25~2.3.10.3.0.1.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.25~2.3.10.3.0.1.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.25~2.3.10.3.0.1.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.25~2.3.10.3.0.1.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.25~2.3.10.3.0.1.el6_4", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

