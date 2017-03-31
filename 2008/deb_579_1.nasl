# OpenVAS Vulnerability Test
# $Id: deb_579_1.nasl 4004 2016-09-08 05:36:24Z teissa $
# Description: Auto-generated from advisory DSA 579-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_insight = "A buffer overflow vulnerability has been disovered in the wv library,
used for converting and previewing word documents.  On exploition an
attacker could execute arbitrary code with the privileges of the user
running the vulnerable application.

For the stable distribution (woody) this problem has been fixed in
version 1.0.2+cvs.2002.06.05-1woody2.

The package in the unstable distribution (sid) is not affected.

We recommend that you upgrade your abiword package.";
tag_summary = "The remote host is missing an update to abiword
announced via advisory DSA 579-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20579-1";

if(description)
{
 script_id(53271);
 script_version("$Revision: 4004 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-08 07:36:24 +0200 (Thu, 08 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0645");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Debian Security Advisory DSA 579-1 (abiword)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"abiword-doc", ver:"1.0.2+cvs.2002.06.05-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xfonts-abi", ver:"1.0.2+cvs.2002.06.05-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abiword", ver:"1.0.2+cvs.2002.06.05-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abiword-common", ver:"1.0.2+cvs.2002.06.05-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abiword-gnome", ver:"1.0.2+cvs.2002.06.05-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abiword-gtk", ver:"1.0.2+cvs.2002.06.05-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"abiword-plugins", ver:"1.0.2+cvs.2002.06.05-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
