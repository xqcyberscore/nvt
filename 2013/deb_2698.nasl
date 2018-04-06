# OpenVAS Vulnerability Test
# $Id: deb_2698.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2698-1 using nvtgen 1.0
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

tag_affected  = "tiff on Debian Linux";
tag_insight   = "libtiff is a library providing support for the Tag Image File Format
(TIFF), a widely used format for storing image data.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 3.9.4-5+squeeze9.

For the stable distribution (wheezy), these problems have been fixed in
version 4.0.2-6+deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 4.0.2-6+nmu1.

We recommend that you upgrade your tiff packages.";
tag_summary   = "Multiple issues were discovered in the TIFF tools, a set of utilities for
TIFF image file manipulation and conversion.

CVE-2013-1960 
Emmanuel Bouillon discovered a heap-based buffer overflow in the
tp_process_jpeg_strip function in the tiff2pdf tool. This could
potentially lead to a crash or arbitrary code execution.

CVE-2013-1961 
Emmanuel Bouillon discovered many stack-based buffer overflows in
the TIFF tools. These issues could potentially lead to a crash or
arbitrary code execution.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892698");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-1960", "CVE-2013-1961");
    script_name("Debian Security Advisory DSA 2698-1 (tiff - buffer overflow)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-06-18 00:00:00 +0200 (Tue, 18 Jun 2013)");
    script_tag(name: "cvss_base", value:"9.3");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2698.html");


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
if ((res = isdpkgvuln(pkg:"libtiff-doc", ver:"3.9.4-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"3.9.4-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"3.9.4-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4", ver:"3.9.4-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff4-dev", ver:"3.9.4-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiffxx0c2", ver:"3.9.4-5+squeeze9", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.0.2-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.0.2-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.0.2-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff5", ver:"4.0.2-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff5-alt-dev", ver:"4.0.2-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.0.2-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.0.2-6+deb7u1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
