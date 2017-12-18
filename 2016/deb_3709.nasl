# OpenVAS Vulnerability Test
# $Id: deb_3709.nasl 8131 2017-12-15 07:30:28Z teissa $
# Auto-generated from advisory DSA 3709-1 using nvtgen 1.0
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
    script_oid("1.3.6.1.4.1.25623.1.0.703709");
    script_version("$Revision: 8131 $");
    script_cve_id("CVE-2016-4738");
    script_name("Debian Security Advisory DSA 3709-1 (libxslt - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-12-15 08:30:28 +0100 (Fri, 15 Dec 2017) $");
    script_tag(name:"creation_date", value:"2016-11-14 17:59:18 +0530 (Mon, 14 Nov 2016)");
    script_tag(name:"cvss_base", value:"9.3");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3709.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "libxslt on Debian Linux");
    script_tag(name: "insight",   value: "XSLT is an XML language for defining
transformations of XML files from XML to some other arbitrary format, such as
XML, HTML, plain text, etc. using standard XSLT stylesheets. libxslt is a C
library which implements XSLT version 1.0.");
    script_tag(name: "solution",  value: "For the stable distribution (jessie),
this problem has been fixed in version 1.1.28-2+deb8u2.

For the testing distribution (stretch), this problem has been fixed
in version 1.1.29-2.

For the unstable distribution (sid), this problem has been fixed in
version 1.1.29-2.

We recommend that you upgrade your libxslt packages.");
    script_tag(name: "summary",   value: "Nick Wellnhofer discovered that the
xsltFormatNumberConversion function in libxslt, an XSLT processing runtime library,
does not properly check for a zero byte terminating the pattern string. This flaw
can be exploited to leak a couple of bytes after the buffer that holds the
pattern string.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libxslt1-dbg:amd64", ver:"1.1.29-2", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxslt1-dbg:i386", ver:"1.1.29-2", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"libxslt1-dev:amd64", ver:"1.1.29-2", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxslt1-dev:i386", ver:"1.1.29-2", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"libxslt1.1:amd64", ver:"1.1.29-2", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxslt1.1:i386", ver:"1.1.29-2", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"python-libxslt1", ver:"1.1.29-2", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-libxslt1-dbg", ver:"1.1.29-2", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xsltproc", ver:"1.1.29-2", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxslt1-dbg:amd64", ver:"1.1.28-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxslt1-dbg:i386", ver:"1.1.28-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"libxslt1-dev:amd64", ver:"1.1.28-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxslt1-dev:i386", ver:"1.1.28-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"libxslt1.1:amd64", ver:"1.1.28-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxslt1.1:i386", ver:"1.1.28-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"python-libxslt1", ver:"1.1.28-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-libxslt1-dbg", ver:"1.1.28-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"xsltproc", ver:"1.1.28-2+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
