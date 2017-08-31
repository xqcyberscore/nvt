# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0381.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.130010");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-15 10:41:29 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0381");
script_tag(name: "insight", value: "Updated moodle package fixes security vulnerabilities: In Moodle before 2.8.8, completed and graded lesson activity was not protected against making new attempts to answer some questions, so students could re-attempt answering questions in the lesson (CVE-2015-5264). In Moodle before 2.8.8, users could delete files uploaded by other users in wiki (CVE-2015-5265). In Moodle before 2.8.8, meta course synchronisation enrols suspended students as managers for a short period of time and causes large database growth. On large installations, when the sync script takes a long time, suspended students may get assigned a manager role in meta course for several minutes (CVE-2015-5266) In Moodle before 2.8.8, password recovery tokens can be guessed because of php randomisation limitations (CVE-2015-5267). In Moodle before 2.8.8, when viewing ratings, the group access was not properly checked, allowing users from other groups to view ratings (CVE-2015-5268). In Moodle before 2.8.8, capability to manage groups does not have XSS risk, however it was possible to add XSS to the grouping description (CVE-2015-5269). The moodle package has been updated to version 2.8.8, fixing these issues and several other bugs. Additionally, the preg plugin has been updated to version 2.8, and the OU Multiple Response question type and UIkit theme have been added to the package."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0381.html");
script_cve_id("CVE-2015-5264","CVE-2015-5265","CVE-2015-5266","CVE-2015-5267","CVE-2015-5268","CVE-2015-5269");
script_tag(name:"cvss_base", value:"5.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0381");
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
if ((res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.8.8~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
