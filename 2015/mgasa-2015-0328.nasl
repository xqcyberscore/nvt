# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0328.nasl 6563 2017-07-06 12:23:47Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.130056");
script_version("$Revision: 6563 $");
script_tag(name:"creation_date", value:"2015-10-15 10:42:08 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:23:47 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0328");
script_tag(name: "insight", value: "Cross-site scripting (XSS) vulnerability in the Autocomplete system in Drupal before 7.39 allows remote attackers to inject arbitrary web script or HTML via a crafted URL, related to uploading files (CVE-2015-6658). SQL injection vulnerability in the SQL comment filtering system in the Database API in Drupal before 7.39 allows remote attackers to execute arbitrary SQL commands via an SQL comment (CVE-2015-6659). The Form API in Drupal 6.x before 6.37 and 7.x before 7.39 does not properly validate the form token, which allows remote attackers to conduct CSRF attacks that upload files in a different user's account via vectors related to file upload value callbacks (CVE-2015-6660). Drupal before 7.39 allows remote attackers to obtain sensitive node titles by reading the menu (CVE-2015-6661). Cross-site scripting (XSS) vulnerability in the Ajax handler in Drupal before 7.39 allows remote attackers to inject arbitrary web script or HTML via vectors involving a whitelisted HTML element, possibly related to the a tag (CVE-2015-6665)."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0328.html");
script_cve_id("CVE-2015-6658","CVE-2015-6659","CVE-2015-6660","CVE-2015-6661","CVE-2015-6665");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0328");
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
if ((res = isrpmvuln(pkg:"drupal", rpm:"drupal~7.39~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
