# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0246.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123727");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:44 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0246");
script_tag(name: "insight", value: "ELSA-2013-0246 -  java-1.6.0-openjdk security update - [ 1:1.6.0.0-1.33.1.11.6.0.1.el5_9]- Add oracle-enterprise.patch[1:1.6.0.0-1.33.1.11.6]- removed patch9 revertTwoWrongSecurityPatches2013-02-06.patch- added patch9: 7201064.patch to be reverted- added patch10: 8005615.patch to fix the 6664509.patch- Resolves: rhbz#906705[1:1.6.0.0-1.32.1.11.6]- added patch9 revertTwoWrongSecurityPatches2013-02-06.patch to remove 6664509 and 7201064 from 1.11.6 tarball- Resolves: rhbz#906705[1:1.6.0.0-1.31.1.11.6]- Updated to icedtea6 1.11.6- Rewritten java-1.6.0-openjdk-java-access-bridge-security.patch- Resolves: rhbz#906705"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0246");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0246.html");
script_cve_id("CVE-2013-0424","CVE-2013-0425","CVE-2013-0426","CVE-2013-0427","CVE-2013-0428","CVE-2013-0429","CVE-2013-0432","CVE-2013-0433","CVE-2013-0434","CVE-2013-0441","CVE-2013-0442","CVE-2013-0443","CVE-2013-0445","CVE-2013-0450","CVE-2013-1475","CVE-2013-1480","CVE-2013-1478","CVE-2013-0435","CVE-2013-0440","CVE-2013-1476");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.33.1.11.6.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.33.1.11.6.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.33.1.11.6.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.33.1.11.6.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.33.1.11.6.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

