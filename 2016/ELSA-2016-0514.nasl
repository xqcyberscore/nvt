# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-0514.nasl 9066 2018-03-09 10:10:37Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.fi
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.122913");
script_version("$Revision: 9066 $");
script_tag(name:"creation_date", value:"2016-03-31 08:06:16 +0300 (Thu, 31 Mar 2016)");
script_tag(name:"last_modification", value:"$Date: 2018-03-09 11:10:37 +0100 (Fri, 09 Mar 2018) $");
script_name("Oracle Linux Local Check: ELSA-2016-0514");
script_tag(name: "insight", value: "ELSA-2016-0514 -  java-1.8.0-openjdk security update - [1:1.8.0.77-0.b03]- Remove what remains of the SunEC sources in the remove-intree-libraries script.- Resolves: rhbz#1320661[1:1.8.0.77-0.b03]- Update to u77b03.- Drop 8146566 which is applied upstream.- Replace s390 Java options patch with general version from IcedTea.- Apply s390 patches unconditionally to avoid arch-specific patch failures.- Remove fragment of s390 size_t patch that unnecessarily removes a cast, breaking ppc64le.- Remove aarch64-specific suffix as update/build version are now the same as for other archs.- Only use z format specifier on s390, not s390x.- Adjust tarball generation script to allow ecc_impl.h to be included.- Correct spelling mistakes in tarball generation script.- Synchronise minor changes from Fedora.- Use a simple backport for PR2462/8074839.- Don't backport the crc check for pack.gz. It's not tested well upstream.- Resolves: rhbz#1320661"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-0514");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-0514.html");
script_cve_id("CVE-2016-0636");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java", rpm:"java~1.8.0~openjdk~debug~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-debug", rpm:"java-1.8.0-openjdk-demo~debug~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-debug", rpm:"java-1.8.0-openjdk-devel~debug~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-debug", rpm:"java-1.8.0-openjdk-headless~debug~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-debug", rpm:"java-1.8.0-openjdk-javadoc~debug~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-src-debug", rpm:"java-1.8.0-openjdk-src~debug~1.8.0.77~0.b03.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

