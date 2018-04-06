# OpenVAS Vulnerability Test
# $Id: deb_2750.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2750-1 using nvtgen 1.0
# Script version: 1.0
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

tag_affected  = "imagemagick on Debian Linux";
tag_insight   = "ImageMagick is a software suite to create, edit, and compose bitmap images.
It can read, convert and write images in a variety of formats (over 100)
including DPX, EXR, GIF, JPEG, JPEG-2000, PDF, PhotoCD, PNG, Postscript,
SVG, and TIFF. Use ImageMagick to translate, flip, mirror, rotate, scale,
shear and transform images, adjust image colors, apply various special
effects, or draw text, lines, polygons, ellipses and Bézier curves.
All manipulations can be achieved through shell commands as well as through
an X11 graphical interface (display).";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in
version 8:6.7.7.10-5+deb7u2.

For the unstable distribution (sid), this problem has been fixed in
version 8:6.7.7.10-6.

We recommend that you upgrade your imagemagick packages.";
tag_summary   = "Anton Kortunov reported a heap corruption in ImageMagick, a program
collection and library for converting and manipulating image files.
Crafted GIF files could cause ImageMagick to crash, potentially
leading to arbitrary code execution.

The oldstable distribution (squeeze) is not affected by this problem.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892750");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-4298");
    script_name("Debian Security Advisory DSA 2750-1 (imagemagick - buffer overflow)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-09-03 00:00:00 +0200 (Tue, 03 Sep 2013)");
    script_tag(name: "cvss_base", value:"4.3");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2750.html");


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
if ((res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick-dbg", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++5", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickcore5", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickcore5-extra", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickwand5", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.7.7.10-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
