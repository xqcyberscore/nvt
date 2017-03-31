# OpenVAS Vulnerability Test
# $Id: deb_037_1.nasl 3854 2016-08-18 13:15:25Z teissa $
# Description: Auto-generated from advisory DSA 037-1
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
tag_insight = "It has been reported that the AsciiSrc and MultiSrc widget in the
Athena widget library handle temporary files insecurely.  Joey Hess
has ported the bugfix from XFree86 to these Xaw replacements
libraries.

We recommend you upgrade your nextaw, xaw3d and xaw95 packages.";
tag_summary = "The remote host is missing an update to nextaw, xaw3d, xaw95
announced via advisory DSA 037-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20037-1";

if(description)
{
 script_id(53799);
 script_version("$Revision: 3854 $");
 script_tag(name:"last_modification", value:"$Date: 2016-08-18 15:15:25 +0200 (Thu, 18 Aug 2016) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_name("Debian Security Advisory DSA 037-1 (nextaw, xaw3d, xaw95)");



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
if ((res = isdpkgvuln(pkg:"nextaw", ver:"0.5.1-34potato1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nextawg", ver:"0.5.1-34potato1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xaw3d", ver:"1.3-6.9potato1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xaw3dg-dev", ver:"1.3-6.9potato1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xaw3dg", ver:"1.3-6.9potato1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xaw95g", ver:"1.1-4.6potato1", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
