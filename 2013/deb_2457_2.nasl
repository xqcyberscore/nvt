# OpenVAS Vulnerability Test
# $Id: deb_2457_2.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2457-2 using nvtgen 1.0
# Script version: 2.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_affected  = "iceweasel on Debian Linux";
tag_insight   = "Firefox is a redesign of the Mozilla browser component, similar to
Galeon, K-Meleon and Camino, but written using the XUL user interface
language and designed to be lightweight and cross-platform.";
tag_solution  = "For the stable distribution (squeeze), this problem has been fixed in
version 3.5.16-15.

For the unstable distribution (sid), this problem has been fixed in
version 10.0.4esr-1.

For the experimental distribution, this problem will be fixed soon.

We recommend that you upgrade your iceweasel packages.";
tag_summary   = "Several vulnerabilities have been discovered in Iceweasel, a web
browser based on Firefox. The included XULRunner library provides
rendering services for several other applications included in Debian.

CVE-2012-0467Bob Clary, Christian Holler, Brian Hackett, Bobby Holley, Gary
Kwong, Hilary Hall, Honza Bambas, Jesse Ruderman, Julian Seward,
and Olli Pettay discovered memory corruption bugs, which may lead
to the execution of arbitrary code.

CVE-2012-0470Atte Kettunen discovered that a memory corruption bug in
gfxImageSurface may lead to the execution of arbitrary code.

CVE-2012-0471Anne van Kesteren discovered that incorrect multibyte character
encoding may lead to cross-site scripting.

CVE-2012-0477Masato Kinugawa discovered that incorrect encoding of
Korean and Chinese character sets may lead to cross-site scripting.

CVE-2012-0479Jeroen van der Gun discovered a spoofing vulnerability in the
presentation of Atom and RSS feeds over HTTPS.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892457");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2012-0477", "CVE-2012-0471", "CVE-2012-0479", "CVE-2012-0470", "CVE-2012-0467");
    script_name("Debian Security Advisory DSA 2457-2 (iceweasel - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name:"creation_date", value:"2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)");
    script_tag(name: "cvss_base", value:"10.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2012/dsa-2457.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: tag_affected);
    script_tag(name: "insight",   value: tag_insight);
#    script_tag(name: "impact",    value: tag_impact);
    script_tag(name: "solution",  value: tag_solution);
    script_tag(name: "summary",   value: tag_summary);
    script_tag(name: "vuldetect", value: tag_vuldetect);
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");

    exit(0);
}

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"iceweasel", ver:"3.5.16-15", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"3.5.16-15", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"3.5.16-15", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs2d", ver:"3.5.16-15", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmozjs2d-dbg", ver:"3.5.16-15", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"3.5.16-15", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9.1", ver:"3.5.16-15", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-1.9.1-dbg", ver:"3.5.16-15", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"3.5.16-15", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
