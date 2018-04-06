# OpenVAS Vulnerability Test
# $Id: deb_3861.nasl 9356 2018-04-06 07:17:02Z cfischer $
# Auto-generated from advisory DSA 3861-1 using nvtgen 1.0
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
    script_oid("1.3.6.1.4.1.25623.1.0.703861");
    script_version("$Revision: 9356 $");
    script_cve_id("CVE-2017-6891");
    script_name("Debian Security Advisory DSA 3861-1 (libtasn1-6 - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:17:02 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2017-05-24 00:00:00 +0200 (Wed, 24 May 2017)");
    script_tag(name:"cvss_base", value:"6.8");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2017/dsa-3861.html");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "libtasn1-6 on Debian Linux");
        script_tag(name: "insight",   value: "Manage ASN1 (Abstract Syntax Notation One) structures.
The main features of this library are:

* on-line ASN1 structure management that doesn't require any C code
file generation.
* off-line ASN1 structure management with C code file generation
containing an array.
* DER (Distinguish Encoding Rules) encoding
* no limits for INTEGER and ENUMERATED values");
    script_tag(name: "solution",  value: "For the stable distribution (jessie), this problem has been fixed in
version 4.2-3+deb8u3.

We recommend that you upgrade your libtasn1-6 packages.");
    script_tag(name: "summary",   value: "Jakub Jirasek of Secunia Research discovered that libtasn1, a library
used to handle Abstract Syntax Notation One structures, did not
properly validate its input. This would allow an attacker to cause a
crash by denial-of-service, or potentially execute arbitrary code, by
tricking a user into processing a maliciously crafted assignments
file.");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");

    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libtasn1-3-bin", ver:"4.2-3+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtasn1-6", ver:"4.2-3+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtasn1-6-dbg", ver:"4.2-3+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtasn1-6-dev", ver:"4.2-3+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtasn1-bin", ver:"4.2-3+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtasn1-doc", ver:"4.2-3+deb8u3", rls_regex:"DEB8.[0-9]+", remove_arch:TRUE )) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
