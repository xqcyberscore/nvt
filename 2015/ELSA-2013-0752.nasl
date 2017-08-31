# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0752.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123638");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:37 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0752");
script_tag(name: "insight", value: "ELSA-2013-0752 -  java-1.7.0-openjdk security update - [1.7.0.19-2.3.9.1.0.1.el5_9] - Add oracle-enterprise.patch - Fix DISTRO_NAME to Enterprise Linux [1.7.0.19-2.3.9.1.el5] - updated to updated IcedTea 2.3.9 with fix to one of security fixes - fixed font glyph offset - Resolves: rhbz#950376 [1.7.0.19-2.3.9.0.el5] - updated to IcedTea 2.3.9 with latest security patches - buildver sync to b19 - rewritten java-1.7.0-openjdk-java-access-bridge-security.patch - Resolves: rhbz#950376 [1.7.0.9-2.3.8.1.el5] - Added some of the latest Fedora spec bugfixes - Bumped release - zlib in BuildReq restricted for 1.2.3-7 or higher - see https://bugzilla.redhat.com/show_bug.cgi?id=904231 - Removed a -icedtea tag from the version - package have less and less connections to icedtea7 - Added gcc-c++ build dependence. Sometimes caused troubles during rpm -bb - Added (Build)Requires for fontconfig and xorg-x11-fonts-Type1 - see https://bugzilla.redhat.com/show_bug.cgi?id=721033 for details - logging.properties marked as config(noreplace) - see https://bugzilla.redhat.com/show_bug.cgi?id=679180 for details - nss.cfg was marked as config(noreplace) - slaves sync with el6 - Resolves: rhbz#950376"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0752");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0752.html");
script_cve_id("CVE-2013-0401","CVE-2013-1488","CVE-2013-1518","CVE-2013-1537","CVE-2013-1557","CVE-2013-1558","CVE-2013-1569","CVE-2013-2383","CVE-2013-2384","CVE-2013-2415","CVE-2013-2417","CVE-2013-2419","CVE-2013-2420","CVE-2013-2421","CVE-2013-2422","CVE-2013-2423","CVE-2013-2424","CVE-2013-2426","CVE-2013-2429","CVE-2013-2430","CVE-2013-2431","CVE-2013-2436");
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
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk", rpm:"java-1.7.0-openjdk~1.7.0.19~2.3.9.1.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-demo", rpm:"java-1.7.0-openjdk-demo~1.7.0.19~2.3.9.1.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-devel", rpm:"java-1.7.0-openjdk-devel~1.7.0.19~2.3.9.1.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-javadoc", rpm:"java-1.7.0-openjdk-javadoc~1.7.0.19~2.3.9.1.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.7.0-openjdk-src", rpm:"java-1.7.0-openjdk-src~1.7.0.19~2.3.9.1.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

