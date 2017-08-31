# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0271.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123723");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:07:41 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0271");
script_tag(name: "insight", value: "ELSA-2013-0271 -  firefox security update - firefox[17.0.3-1.0.1]- Add firefox-oracle-default-prefs.js and remove the corresponding Red Hat ones[17.0.3-1]- Update to 17.0.3 ESR[17.0.2-4]- Added NM preferences[17.0.2-3]- Update to 17.0.2 ESR[17.0.1-2]- Update to 17.0.1 ESR[17.0-1]- Update to 17.0 ESR[17.0-0.2.b4]- Update to 17 Beta 4[17.0-0.1.beta1]- Update to 17 Beta 1libproxy[0.3.0-4]- Rebuild against newer geckoxulrunner[17.0.3-1.0.2]- Increase release number and rebuild.[17.0.3-1.0.1]- Replaced xulrunner-redhat-default-prefs.js with xulrunner-oracle-default-prefs.js- Removed XULRUNNER_VERSION from SOURCE21[17.0.3-1]- Update to 17.0.3 ESR[17.0.2-5]- Fixed NetworkManager preferences- Added fix for NM regression (mozbz#791626)[17.0.2-2]- Added fix for rhbz#816234 - NFS fix[17.0.2-1]- Update to 17.0.2 ESR[17.0.1-3]- Update to 17.0.1 ESR[17.0-1]- Update to 17.0 ESR[17.0-0.6.b5]- Update to 17 Beta 5- Updated fix for rhbz#872752 - embeded crash[17.0-0.5.b4]- Added fix for rhbz#872752 - embeded crash[17.0-0.4.b4]- Update to 17 Beta 4[17.0-0.3.b3]- Update to 17 Beta 3- Updated ppc(64) patch (mozbz#746112)[17.0-0.2.b2]- Built with system nspr/nss[17.0-0.1.b2]- Update to 17 Beta 2[17.0-0.1.b1]- Update to 17 Beta 1yelp[2.28.1-17]- Rebuild against gecko 17.0.2[2.28.1-15]- Build fixes for gecko 17"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0271");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0271.html");
script_cve_id("CVE-2013-0775","CVE-2013-0776","CVE-2013-0780","CVE-2013-0782","CVE-2013-0783");
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
  if ((res = isrpmvuln(pkg:"devhelp", rpm:"devhelp~0.12~23.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"devhelp-devel", rpm:"devhelp-devel~0.12~23.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~17.0.3~1.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~17.0.3~1.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~17.0.3~1.0.1.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"yelp", rpm:"yelp~2.16.0~30.el5_9", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~17.0.3~1.0.1.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libproxy", rpm:"libproxy~0.3.0~4.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libproxy-bin", rpm:"libproxy-bin~0.3.0~4.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libproxy-devel", rpm:"libproxy-devel~0.3.0~4.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libproxy-gnome", rpm:"libproxy-gnome~0.3.0~4.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libproxy-kde", rpm:"libproxy-kde~0.3.0~4.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libproxy-mozjs", rpm:"libproxy-mozjs~0.3.0~4.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libproxy-python", rpm:"libproxy-python~0.3.0~4.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"libproxy-webkit", rpm:"libproxy-webkit~0.3.0~4.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~17.0.3~1.0.2.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~17.0.3~1.0.2.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"yelp", rpm:"yelp~2.28.1~17.el6_3", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

