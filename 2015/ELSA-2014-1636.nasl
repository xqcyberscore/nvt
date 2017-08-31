# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1636.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123269");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:01:32 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1636");
script_tag(name: "insight", value: "ELSA-2014-1636 -  java-1.8.0-openjdk security update - [1:1.8.0.25-1.b17] - Update to October CPU patch update. - Resolves: RHBZ#1148896 [1:1.8.0.20-3.b26] - fixed headless (policytool moved to normal) - jre/bin/policytool added to not headless exclude list - updated aarch694 source - ppc64le synced from fedora - Resolves: rhbz#1081073 [1:1.8.0.20-2.b26] - forcing build by itself (jdk8 by jdk8) - Resolves: rhbz#1081073 [1:1.8.0.20-1.b26] - updated to u20-b26 - adapted patch9999 enableArm64.patch - adapted patch100 s390-java-opts.patch - adapted patch102 size_t.patch - removed upstreamed patch 0001-PPC64LE-arch-support-in-openjdk-1.8.patch - adapted system-lcms.patch - removed patch8 set-active-window.patch - removed patch9 javadoc-error-jdk-8029145.patch - removed patch10 javadoc-error-jdk-8037484.patch - removed patch99 applet-hole.patch - itw 1.5.1 is able to ive without it - Resolves: rhbz#1081073 [1:1.8.0.11-19.b12] - fixed desktop icons - Icon set to java-1.8.0 - Development removed from policy tool - Resolves: rhbz#1081073 [1:1.8.0.11-18.b12] - fixed jstack - Resolves: rhbz#1081073 [1:1.8.0.11-15.b12] - fixed provides/obsolates - Resolves: rhbz#1081073 [1:1.8.0.11-14.b12] - mayor rework of specfile - sync with f21 - accessibility kept removed - lua script kept unsync - priority and epoch kept on 0 - not included disable-doclint patch - kept bundled lcms - unused OrderWithRequires - used with-stdcpplib instead of with-stdc++lib - Resolves: rhbz#1081073 [1:1.8.0.11-4.b13] - Added security patches - Resolves: rhbz#1081073 [1:1.8.0.5-6.b13] - Removed accessibility package - removed patch3 java-atk-wrapper-security.patch - removed its files and declaration - removed creation of libatk-wrapper.so and java-atk-wrapper.jar symlinks - removed generation of accessibility.properties - Resolves: rhbz#1113078 [1:1.8.0.5-5.b13] - priority lowered to 00000 - Resolves: rhbz#1081073 [1:1.8.0.5-4.b13] - Initial import from fedora - Used bundled lcms2 - added java-1.8.0-openjdk-disable-system-lcms.patch - --with-lcms changed to bundled - removed build requirement - excluded removal of lcms from remove-intree-libraries.sh - removed --with-extra-cflags=-fno-devirtualize and --with-extra-cxxflags=-fn o-devirtualize--- - added patch998, rhel6-built.patch to - fool autotools - replace all ++ chars in autoconfig files by pp - --with-stdc++lib=dynamic replaced by --with-stdcpplib=dynamic - Bumped release - Set epoch to 0 - removed patch6, disable-doclint-by-default.patch - Resolves: rhbz#1081073"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1636");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1636.html");
script_cve_id("CVE-2014-6457","CVE-2014-6502","CVE-2014-6504","CVE-2014-6506","CVE-2014-6511","CVE-2014-6512","CVE-2014-6517","CVE-2014-6519","CVE-2014-6531","CVE-2014-6558","CVE-2014-6468","CVE-2014-6562");
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
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.25~1.b17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.25~1.b17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.25~1.b17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.25~1.b17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.25~1.b17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.25~1.b17.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

