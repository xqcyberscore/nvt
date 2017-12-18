# OpenVAS Vulnerability Test
# $Id: deb_3547.nasl 8131 2017-12-15 07:30:28Z teissa $
# Auto-generated from advisory DSA 3547-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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


if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.703547");
    script_version("$Revision: 8131 $");
    
    script_name("Debian Security Advisory DSA 3547-1 (imagemagick - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-12-15 08:30:28 +0100 (Fri, 15 Dec 2017) $");
    script_tag(name: "creation_date", value: "2016-04-11 00:00:00 +0200 (Mon, 11 Apr 2016)");
    script_tag(name: "cvss_base", value: "10.0");
    script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3547.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "imagemagick on Debian Linux");
    script_tag(name: "insight",   value: "ImageMagick is a software suite
to create, edit, and compose bitmap images. It can read, convert and write
images in a variety of formats (over 100) including DPX, EXR, GIF, JPEG, JPEG-2000,
PDF, PhotoCD, PNG, Postscript, SVG, and TIFF. Use ImageMagick to translate, flip,
mirror, rotate, scale, shear and transform images, adjust image colors, apply
various special effects, or draw text, lines, polygons, ellipses and Bezier curves.
All manipulations can be achieved through shell commands as well as through
an X11 graphical interface (display).");
    script_tag(name: "solution",  value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 8:6.7.7.10-5+deb7u4.

For the stable distribution (jessie), this problem was already fixed in
version 8:6.8.9.9-5+deb8u1, in the last point release.

We recommend that you upgrade your imagemagick packages.");
    script_tag(name: "summary",   value: "Several vulnerabilities were discovered in
Imagemagick, a program suite for image manipulation. This update fixes a large number
of potential security problems such as null-pointer access and buffer-overflows that
might lead to memory leaks or denial of service. None of these security problems have
a CVE number assigned.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"imagemagick", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick-common", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick-dbg", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"imagemagick-doc", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++-dev", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++5:i386", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagick++5:amd64", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"libmagickcore-dev", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickcore5:i386", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickcore5:amd64", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"libmagickcore5-extra:i386", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickcore5-extra:amd64", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"libmagickwand-dev", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickwand5:i386", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmagickwand5:amd64", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"perlmagick", ver:"8:6.7.7.10-5+deb7u4", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
