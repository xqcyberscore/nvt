# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2015-0378.nasl 6170 2017-05-19 09:03:42Z teissa $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.130013");
script_version("$Revision: 6170 $");
script_tag(name:"creation_date", value:"2015-10-15 10:41:31 +0300 (Thu, 15 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-05-19 11:03:42 +0200 (Fri, 19 May 2017) $");
script_name("Mageia Linux Local Check: mgasa-2015-0378");
script_tag(name: "insight", value: "Updated owncloud package fixes security vulnerabilities: In ownCloud before 8.0.6, due to an incorrect usage of an ownCloud internal file system function the passed path to the file scanner was resolved relatively. An authenticated adversary may thus be able to get a listing of directories (but not the containing files) existing on the filesystem. However, it is not possible to access any of these files (CVE-2015-6500). In ownCloud before 8.0.6, due to not properly checking the ownership of an calendar, an authenticated attacker is able to download calendars of other users via the calid GET parameter to export.php in /apps/calendar/ (CVE-2015-6670). The owncloud package has been updated to version 8.0.8, which fixes these issues, as well as other bugs and other not-yet-disclosed security issues."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2015-0378.html");
script_cve_id("CVE-2015-6500","CVE-2015-6670");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("login/SSH/success", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2015-0378");
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
if ((res = isrpmvuln(pkg:"owncloud", rpm:"owncloud~8.0.8~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
