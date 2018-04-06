# OpenVAS Vulnerability Test
# $Id: deb_3864.nasl 9356 2018-04-06 07:17:02Z cfischer $
# Auto-generated from advisory DSA 3864-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
    script_oid("1.3.6.1.4.1.25623.1.0.703864");
    script_version("$Revision: 9356 $");
    script_cve_id("CVE-2017-5661");
    script_name("Debian Security Advisory DSA 3864-1 (fop - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:17:02 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2017-05-27 00:00:00 +0200 (Sat, 27 May 2017)");
    script_tag(name:"cvss_base", value:"7.9");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:N/A:C");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2017/dsa-3864.html");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "fop on Debian Linux");
        script_tag(name: "insight",   value: "FOP is a Java application that reads a formatting object tree and then
turns it into a wide variety of output presentations (including AFP,
PCL, PDF, PNG, PostScript, RTF, TIFF, and plain text), or displays
the result on-screen.");
    script_tag(name: "solution",  value: "For the stable distribution (jessie), this problem has been fixed in
version 1:1.1.dfsg2-1+deb8u1.

For the upcoming stable distribution (stretch), this problem has been
fixed in version 1:2.1-6.

For the unstable distribution (sid), this problem has been fixed in
version 1:2.1-6.

We recommend that you upgrade your fop packages.");
    script_tag(name: "summary",   value: "It was discovered that an XML external entities vulnerability in the
Apache FOP XML formatter may result in information disclosure.");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");

    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"fop", ver:"1:2.1-6", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fop-doc", ver:"1:2.1-6", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libfop-java", ver:"1:2.1-6", rls_regex:"DEB9.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fop", ver:"1:1.1.dfsg2-1+deb8u1", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fop-doc", ver:"1:1.1.dfsg2-1+deb8u1", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libfop-java", ver:"1:1.1.dfsg2-1+deb8u1", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
