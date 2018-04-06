# OpenVAS Vulnerability Test
# $Id: deb_2844.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2844-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
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

tag_affected  = "djvulibre on Debian Linux";
tag_solution  = "For the oldstable distribution (squeeze), this problem has been fixed in
version 3.5.23-3+squeeze1.

This problem has been fixed before the release of the stable distribution
(wheezy), therefore it is not affected.

We recommend that you upgrade your djvulibre packages.";
tag_summary   = "It was discovered that djvulibre, the Open Source DjVu implementation
project, can be crashed or possibly make it execute arbitrary code when
processing a specially crafted djvu file.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702844");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2012-6535");
    script_name("Debian Security Advisory DSA 2844-1 (djvulibre - arbitrary code execution)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-01-15 00:00:00 +0100 (Wed, 15 Jan 2014)");
    script_tag(name: "cvss_base", value:"9.3");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2844.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: tag_affected);
#    script_tag(name: "impact",    value: tag_impact);
    script_tag(name: "solution",  value: tag_solution);
    script_tag(name: "summary",   value: tag_summary);
    script_tag(name: "vuldetect", value: tag_vuldetect);
    script_tag(name:"qod_type", value:"package");
    script_tag(name:"solution_type", value:"VendorFix");

    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"djview", ver:"3.5.23-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"djview3", ver:"3.5.23-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"djvulibre-bin", ver:"3.5.23-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"djvulibre-dbg", ver:"3.5.23-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"djvulibre-desktop", ver:"3.5.23-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"djvulibre-plugin", ver:"3.5.23-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"djvuserve", ver:"3.5.23-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdjvulibre-dev", ver:"3.5.23-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdjvulibre-text", ver:"3.5.23-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdjvulibre21", ver:"3.5.23-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
