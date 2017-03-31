# OpenVAS Vulnerability Test
# $Id: deb_660_1.nasl 4015 2016-09-09 05:53:53Z teissa $
# Description: Auto-generated from advisory DSA 660-1
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
tag_insight = "Raphaël Enrici discovered that the KDE screensaver can crash under
certain local circumstances.  This can be exploited by an attacker
with physical access to the workstation to take over the desktop
session.

For the stable distribution (woody) this problem has been fixed in
version 2.2.2-14.9.

This problem has been fixed upstream in KDE 3.0.5 and is therefore
fixed in the unstable (sid) and testing (sarge) distributions already.

We recommend that you upgrade your kscreensaver package.";
tag_summary = "The remote host is missing an update to kdebse
announced via advisory DSA 660-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20660-1";

if(description)
{
 script_id(53491);
 script_version("$Revision: 4015 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-09 07:53:53 +0200 (Fri, 09 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:56:38 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-0078");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 660-1 (kdebse)");



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
if ((res = isdpkgvuln(pkg:"kdebase-doc", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdewallpapers", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kate", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdebase", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdebase-audiolibs", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdebase-dev", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdebase-libs", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kdm", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"konqueror", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"konsole", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kscreensaver", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkonq-dev", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkonq3", ver:"2.2.2-14.9", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
