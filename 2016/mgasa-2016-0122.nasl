# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0122.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://www.solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.131276");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-03-31 08:05:01 +0300 (Thu, 31 Mar 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0122");
script_tag(name: "insight", value: "In Moodle before 2.8.11, teachers who otherwise were not supposed to see students' emails could see them in the participants list (CVE-2016-2151). In Moodle before 2.8.11, Moodle traditionally trusted content from external DB, however it was decided that external datasources may not be aware of web security practices and data could cause problems after importing to Moodle (CVE-2016-2152). In Moodle before 2.8.11, a user with higher permissions could be tricked into clicking a link which would result in Reflected XSS in mod_data advanced search (CVE-2016-2153). In Moodle before 2.8.11, users without capability to view hidden courses but with capability to subscribe to Event Monitor rules could see the names of hidden courses (CVE-2016-2154). In Moodle before 2.8.11, the Non-Editing Instructor role can edit the exclude checkbox in the Single View grade report (CVE-2016-2155). In Moodle before 2.8.11, users without the capability to view hidden acitivites could still see associated calendar events via web services, via the external function get_calendar_events (CVE-2016-2156). In Moodle before 2.8.11, CSRF is possible on the Assignment plugin admin page, however an exploit is unlikely to benefit anybody and can easily be reversed (CVE-2016-2157). In Moodle before 2.8.11, enumeration of course category details is possible without authentication (CVE-2016-2158). In Moodle before 2.8.11, students were able to add assignment submissions after the due date through web service, via the external function mod_assign_save_submission (CVE-2016-2159). In Moodle before 2.8.11, when following external links that were added with the _blank target, a referer header would be added (CVE-2016-2190)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0122.html");
script_cve_id("CVE-2016-2151","CVE-2016-2152","CVE-2016-2153","CVE-2016-2154","CVE-2016-2155","CVE-2016-2156","CVE-2016-2157","CVE-2016-2158","CVE-2016-2159","CVE-2016-2190");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0122");
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
if ((res = isrpmvuln(pkg:"moodle", rpm:"moodle~2.8.11~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
