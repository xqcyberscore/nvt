# OpenVAS Vulnerability Test
# $Id: deb_3538.nasl 3604 2016-06-27 05:18:57Z antu123 $
# Auto-generated from advisory DSA 3538-1 using nvtgen 1.0
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
    script_id(703538);
    script_version("$Revision: 3604 $");
    script_cve_id("CVE-2015-8789", "CVE-2015-8790", "CVE-2015-8791");
    script_name("Debian Security Advisory DSA 3538-1 (libebml - security update)");
    script_tag(name: "last_modification", value: "$Date: 2016-06-27 07:18:57 +0200 (Mon, 27 Jun 2016) $");
    script_tag(name: "creation_date", value: "2016-03-31 00:00:00 +0200 (Thu, 31 Mar 2016)");
    script_tag(name:"cvss_base", value:"9.3");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3538.html");

    script_summary("Debian Security Advisory DSA 3538-1 (libebml - security update)");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
    script_tag(name: "affected",  value: "libebml on Debian Linux");
    script_tag(name: "solution",  value: "For the oldstable distribution (wheezy),
these problems have been fixed in version 1.2.2-2+deb7u1.

For the stable distribution (jessie), these problems have been fixed in
version 1.3.0-2+deb8u1.

For the testing (stretch) and unstable (sid) distributions, these
problems have been fixed in version 1.3.3-1.

We recommend that you upgrade your libebml packages.");
    script_tag(name: "summary",   value: "Several vulnerabilities were
discovered in libebml, a library for manipulating Extensible Binary Meta
Language files.

CVE-2015-8789 
Context-dependent attackers could trigger a use-after-free
vulnerability by providing a maliciously crafted EBML document.

CVE-2015-8790 
Context-dependent attackers could obtain sensitive information
from the process' heap memory by using a maliciously crafted UTF-8
string.

CVE-2015-8791 
Context-dependent attackers could obtain sensitive information
from the process' heap memory by using a maliciously crafted
length value in an EBML id.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libebml-dev:amd64", ver:"1.3.3-1", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebml-dev:i386", ver:"1.3.3-1", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebml4v5", ver:"1.3.3-1", rls_regex:"DEB9.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebml-dev:amd64", ver:"1.3.0-2+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebml-dev:i386", ver:"1.3.0-2+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebml4:amd64", ver:"1.3.0-2+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebml4:i386", ver:"1.3.0-2+deb8u1", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"libebml-dev:amd64", ver:"1.2.2-2+deb7u1", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebml-dev:i386", ver:"1.2.2-2+deb7u1", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"libebml3:amd64", ver:"1.2.2-2+deb7u1", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libebml3:i386", ver:"1.2.2-2+deb7u1", rls_regex:"DEB7.[0-9]+")) != NULL) {
    report += res;
}


if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
