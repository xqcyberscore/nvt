# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0464.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.131146");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-12-08 11:03:39 +0200 (Tue, 08 Dec 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0464");
script_tag(name: "insight", value: "In Moodle before 2.8.9, if guest access is open on the site, unauthenticated users can store Atto draft data through the editor autosave area, which could be exploited in a denial of service attack (CVE-2015-5332). In Moodle before 2.8.9, due to a CSRF issue in the site registration form, it is possible to trick a site admin into sending aggregate stats to an arbitrary domain. The attacker can send the admin a link to a site registration form that will display the correct URL but, if submitted, will register with another hub (CVE-2015-5335). In Moodle before 2.8.9, the standard survey module is vulnerable to XSS attack by students who fill the survey (CVE-2015-5336). In Moodle before 2.8.9, there was a reflected XSS vulnerability in the Flowplayer flash video player (CVE-2015-5337). In Moodle before 2.8.9, password-protected lesson modules are subject to a CSRF vulnerability in the lesson login form (CVE-2015-5338). In Moodle before 2.8.9, through web service core_enrol_get_enrolled_users it is possible to retrieve list of course participants who would not be visible when using web site (CVE-2015-5339). In Moodle before 2.8.9, logged in users who do not have capability 'View available badges without earning them' can still access the full list of badges (CVE-2015-5340). In Moodle before 2.8.9, the SCORM module allows to bypass access restrictions based on date and lets users view the SCORM contents (CVE-2015-5341). In Moodle before 2.8.9, the choice module closing date can be bypassed, allowing users to delete or submit new responses after the choice module was closed (CVE-2015-5342)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0464.html");
script_cve_id("CVE-2015-5332","CVE-2015-5335","CVE-2015-5336","CVE-2015-5337","CVE-2015-5338","CVE-2015-5339","CVE-2015-5340","CVE-2015-5341","CVE-2015-5342");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0464");
script_copyright("Eero Volotinen");
script_family("Mageia Linux Local Security Checks");
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
if(release == "MAGEIA5")
{
if ((res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.8.9~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
