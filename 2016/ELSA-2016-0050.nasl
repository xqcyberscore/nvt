# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-0050.nasl 9066 2018-03-09 10:10:37Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122850");
script_version("$Revision: 9066 $");
script_tag(name:"creation_date", value:"2016-01-21 07:29:48 +0200 (Thu, 21 Jan 2016)");
script_tag(name:"last_modification", value:"$Date: 2018-03-09 11:10:37 +0100 (Fri, 09 Mar 2018) $");
script_name("Oracle Linux Local Check: ELSA-2016-0050");
script_tag(name: "insight", value: "ELSA-2016-0050 -  java-1.8.0-openjdk security update - [1:1.8.0.71-1.b15]- Add patch to turn off strict overflow on IndicRearrangementProcessor{,2}.cpp- Resolves: rhbz#1295751[1:1.8.0.71-0.b15]- January 2016 security update to u71b15.- Improve verbosity and helpfulness of tarball generation script.- Update patch documentation using version originally written for Fedora.- Drop prelink requirement as we no longer use execstack.- Drop ifdefbugfix patch as this is fixed upstream.- Provide optional boostrap build and turn it off by default.- Add patch for size_t formatting on s390 as size_t != intptr_t there.- Resolves: rhbz#1295751[1:1.8.0.65-4.b17]- Add flag logic back to spec file but disable for now.- Restore system-lcms.patch as used in October CPU.- Resolves: rhbz#1295751[1:1.8.0.65-3.b17]- moved to integration forest- sync with rhel7- Resolves: rhbz#1295751"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-0050");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-0050.html");
script_cve_id("CVE-2015-7575","CVE-2016-0402","CVE-2016-0448","CVE-2016-0466","CVE-2016-0475","CVE-2016-0483","CVE-2016-0494");
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
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java", rpm:"java~1.8.0~openjdk~debug~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo-debug", rpm:"java-1.8.0-openjdk-demo~debug~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel-debug", rpm:"java-1.8.0-openjdk-devel~debug~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless-debug", rpm:"java-1.8.0-openjdk-headless~debug~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc-debug", rpm:"java-1.8.0-openjdk-javadoc~debug~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"java-1.8.0-openjdk-src-debug", rpm:"java-1.8.0-openjdk-src~debug~1.8.0.71~1.b15.el6_7", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

