# OpenVAS Vulnerability Test 
# Description: Mageia Linux security check 
# $Id: mgasa-2016-0006.nasl 6562 2017-07-06 12:22:42Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.131181");
script_version("$Revision: 6562 $");
script_tag(name:"creation_date", value:"2016-01-14 07:28:54 +0200 (Thu, 14 Jan 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 14:22:42 +0200 (Thu, 06 Jul 2017) $");
script_name("Mageia Linux Local Check: mgasa-2016-0006");
script_tag(name: "insight", value: "Login names (usually an email address) longer than 127 characters are silently truncated in MySQL which could cause the domain name of the email address to be corrupted. An attacker could use this vulnerability to create an account with an email address different from the one originally requested. The login name could then be automatically added to groups based on the group's regular expression setting (CVE-2015-4499). During the generation of a dependency graph, the code for the HTML image map is generated locally if a local dot installation is used. With escaped HTML characters in a bug summary, it is possible to inject unfiltered HTML code in the map file which the CreateImagemap function generates. This could be used for a cross-site scripting attack (CVE-2015-8508). If an external HTML page contains a element with its src attribute pointing to a buglist in CSV format, some web browsers incorrectly try to parse the CSV file as valid JavaScript code. As the buglist is generated based on the privileges of the user logged into Bugzilla, the external page could collect confidential data contained in the CSV file (CVE-2015-8509). The bugzilla package has been updated to version 4.4.11, fixing these issues and a few other bugs."); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://advisories.mageia.org/MGASA-2016-0006.html");
script_cve_id("CVE-2015-4499","CVE-2015-8508","CVE-2015-8509");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name : "summary", value : "Mageia Linux Local Security Checks mgasa-2016-0006");
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
if ((res = isrpmvuln(pkg:"bugzilla", rpm:"bugzilla~4.4.11~1.mga5", rls:"MAGEIA5")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
