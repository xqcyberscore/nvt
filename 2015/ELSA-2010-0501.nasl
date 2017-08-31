# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0501.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122350");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:17:18 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0501");
script_tag(name: "insight", value: "ELSA-2010-0501 -  firefox security, bug fix, and enhancement update - devhelp:[0.12-21]- Rebuild against xulrunneresc:[1.1.0-12]- Rebuild for xulrunner updatefirefox:[3.6.4-8.0.1.el5]- Add firefox-oracle-default-prefs.js and firefox-oracle-default-bookmarks.html and remove the corresponding Red Hat ones[3.6.4-8]- Fixing NVR[3.6.4-7]- Update to 3.6.4 build7- Disable checking for updates since they can't be applied[3.6.4-6]- Update to 3.6.4 build6[3.6.4-5]- Update to 3.6.4 build5[3.6.4-4]- Update to 3.6.4 build4[3.6.4-3]- Update to 3.6.4 build 3[3.6.4-2]- Update to 3.6.4 build 2[3.6.4-1]- Update to 3.6.4[3.6.3-3]- Fixed language packs (#581392)[3.6.3-2]- Fixed multilib conflict[3.6.3-1]- Rebase to 3.6.3gnome-python2-extras:[2.14.2-7]- rebuild agains xulrunnertotem:[2.16.7-7]- rebuild against new xulrunnerxulrunner:[1.9.2.4-9.0.1]- Added xulrunner-oracle-default-prefs.js and removed the corresponding RedHat one.[1.9.2.4-9]- Update to 1.9.2.4 build 7[1.9.2.4-8]- Update to 1.9.2.4 build 6[1.9.2.4-7]- Update to 1.9.2.4 build 5[1.9.2.4-6]- Update to 1.9.2.4 build 4- Fixed mozbz#546270 patch[1.9.2.4-5]- Update to 1.9.2.4 build 3[1.9.2.4-4]- Update to 1.9.2.4 build 2- Enabled oopp[1.9.2.4-3]- Disabled libnotify[1.9.2.4-2]- Disabled oopp, causes TEXTREL[1.9.2.4-1]- Update to 1.9.2.4[1.9.2.3-3]- fixed js-config.h multilib conflict- fixed file list[1.9.2.3-2]- Added fix for rhbz#555760 - Firefox Javascript anomily, landscape print orientation reverts to portrait (mozbz#546270)[1.9.2.3-1]- Update to 1.9.2.3[1.9.2.2-1]- Rebase to 1.9.2.2yelp:[2.16.0-26]- rebuild against xulrunner[2.16.0-25]- rebuild against xulrunner- added xulrunner fix- added -fno-strict-aliasing to build flags"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0501");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0501.html");
script_cve_id("CVE-2008-5913","CVE-2009-5017","CVE-2010-0182","CVE-2010-1121","CVE-2010-1125","CVE-2010-1196","CVE-2010-1197","CVE-2010-1198","CVE-2010-1199","CVE-2010-1200","CVE-2010-1202","CVE-2010-1203");
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
  if ((res = isrpmvuln(pkg:"devhelp", rpm:"devhelp~0.12~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"devhelp-devel", rpm:"devhelp-devel~0.12~21.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"esc", rpm:"esc~1.1.0~12.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.6.4~8.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-extras", rpm:"gnome-python2-extras~2.14.2~7.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-gtkhtml2", rpm:"gnome-python2-gtkhtml2~2.14.2~7.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-gtkmozembed", rpm:"gnome-python2-gtkmozembed~2.14.2~7.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-gtkspell", rpm:"gnome-python2-gtkspell~2.14.2~7.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"gnome-python2-libegg", rpm:"gnome-python2-libegg~2.14.2~7.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"totem", rpm:"totem~2.16.7~7.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"totem-devel", rpm:"totem-devel~2.16.7~7.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"totem-mozplugin", rpm:"totem-mozplugin~2.16.7~7.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.2.4~9.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.2.4~9.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"yelp", rpm:"yelp~2.16.0~26.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

