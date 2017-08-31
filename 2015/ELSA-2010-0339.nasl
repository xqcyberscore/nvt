# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0339.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122367");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:17:38 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0339");
script_tag(name: "insight", value: "ELSA-2010-0339 -  java-1.6.0-openjdk security update - [1:1.6.0.0-1.11.b16.0.1.el5]- Add oracle-enterprise.patch[1:1.6.0.0-1.11.b16.el5]- Remove javaws alternative due to conflict with java-1.6.0-sun's alternatives[1:1.6.0-1.10.b16]- Update to openjdk build b16- Update to icedtea6-1.6- Added tzdata-java requirement- Added autoconf and automake build requirement- Added tzdata-java requirement- Added java-1.6.0-openjdk-gcc-stack-markings.patch- Added java-1.6.0-openjdk-memory-barriers.patch- Added java-1.6.0-openjdk-jar-misc.patch- Added java-1.6.0-openjdk-linux-separate-debuginfo.patch- Added java-1.6.0-openjdk-securitypatches-20100323.patch- Added STRIP_KEEP_SYMTAB=libjvm* to install section, fix bz530402- Resolves: rhbz#576124[1:1.6.0-1.8.b09]- Added java-1.6.0-openjdk-debuginfo.patch- Added java-1.6.0-openjdk-elf-debuginfo.patch"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0339");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0339.html");
script_cve_id("CVE-2009-3555","CVE-2010-0082","CVE-2010-0084","CVE-2010-0085","CVE-2010-0088","CVE-2010-0091","CVE-2010-0092","CVE-2010-0093","CVE-2010-0094","CVE-2010-0095","CVE-2010-0837","CVE-2010-0838","CVE-2010-0840","CVE-2010-0845","CVE-2010-0847","CVE-2010-0848");
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
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.11.b16.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.11.b16.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.11.b16.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.11.b16.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.11.b16.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

