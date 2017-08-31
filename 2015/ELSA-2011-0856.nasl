# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0856.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122147");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:13:51 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0856");
script_tag(name: "insight", value: "ELSA-2011-0856 -  java-1.6.0-openjdk security update - [1.6.0.0-1.39.1.9.8]- Resolves: rhbz#709375- Bumped to IcedTea6 1.9.8- Copy fontconfig files to match names for current and next release- RH706250, S6213702, CVE-2011-0872: (so) non-blocking sockets with TCP urgent disabled get still selected for read ops (win)- RH706106, S6618658, CVE-2011-0865: Vulnerability in deserialization- RH706111, S7012520, CVE-2011-0815: Heap overflow vulnerability in FileDialog.show()- RH706139, S7013519, CVE-2011-0822, CVE-2011-0862: Integer overflows in 2D code- RH706153, S7013969, CVE-2011-0867: NetworkInterface.toString can reveal bindings- RH706234, S7013971, CVE-2011-0869: Vulnerability in SAAJ- RH706239, S7016340, CVE-2011-0870: Vulnerability in SAAJ- RH706241, S7016495, CVE-2011-0868: Crash in Java 2D transforming an image with scale close to zero- RH706248, S7020198, CVE-2011-0871: ImageIcon creates Component with null acc- RH706245, S7020373, CVE-2011-0864: JSR rewriting can overflow memory address size variables"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0856");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0856.html");
script_cve_id("CVE-2011-0862","CVE-2011-0864","CVE-2011-0865","CVE-2011-0867","CVE-2011-0868","CVE-2011-0869","CVE-2011-0871");
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
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.39.1.9.8.el6_1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.39.1.9.8.el6_1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.39.1.9.8.el6_1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.39.1.9.8.el6_1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.39.1.9.8.el6_1", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

