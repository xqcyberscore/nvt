# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1229.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123080");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:59:05 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1229");
script_tag(name: "insight", value: "ELSA-2015-1229 -  java-1.7.0-openjdk security update - [1:1.7.0.85-2.6.1.2.0.1.el7_1]- Update DISTRO_NAME in specfile[1:1.7.0.85-2.6.1.2]- Bump upstream tarball to u25b01 to fix issue with 8075374 backport.- Resolves: rhbz#1235158[1:1.7.0.85-2.6.1.1]- Update OpenJDK tarball so correct version is used.- Resolves: rhbz#1235158[1:1.7.0.85-2.6.1.0]- Add additional java.security md5sum from January CPU- Resolves: rhbz#1235158[1:1.7.0.85-2.6.1.0]- Bump to 2.6.1 and u85b00.- Resolves: rhbz#1235158[1:1.7.0.80-2.6.0.1]- Pass SYSTEM_GSETTINGS='true' to the OpenJDK build to explicitly enable the GSettings API.- Resolves: rhbz#1235158[1:1.7.0.80-2.6.0.0]- Add GConf2-devel dependency for native proxy fallback support.- Remove libxslt dependency pulled in from IcedTea builds.- Reduce redhat-lsb dependency to redhat-lsb-core (lsb_release)- Resolves: rhbz#1235158[1:1.7.0.80-2.6.0.0]- Bump to 2.6.0 and u80b32.- Drop upstreamed patches and separate AArch64 HotSpot.- Add dependencies on pcsc-lite-devel (PR2496) and lksctp-tools-devel (PR2446)- Only run -Xshare:dump on JIT archs other than power64 as port lacks support- Update remove-intree-libraries script to cover LCMS and PCSC headers and SunEC.- Resolves: rhbz#1235158"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1229");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1229.html");
script_cve_id("CVE-2015-4000","CVE-2015-2590","CVE-2015-2601","CVE-2015-2621","CVE-2015-2625","CVE-2015-2628","CVE-2015-2632","CVE-2015-2808","CVE-2015-4731","CVE-2015-4732","CVE-2015-4733","CVE-2015-4748","CVE-2015-4749","CVE-2015-4760");
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
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.85~2.6.1.2.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-accessibility", rpm:"java-1.7.0-openjdk-accessibility~1.7.0.85~2.6.1.2.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.85~2.6.1.2.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.85~2.6.1.2.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-headless", rpm:"java-1.7.0-openjdk-headless~1.7.0.85~2.6.1.2.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.85~2.6.1.2.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.85~2.6.1.2.0.1.el7_1", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.85~2.6.1.3.0.1.el6_6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.85~2.6.1.3.0.1.el6_6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.85~2.6.1.3.0.1.el6_6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.85~2.6.1.3.0.1.el6_6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.85~2.6.1.3.0.1.el6_6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

