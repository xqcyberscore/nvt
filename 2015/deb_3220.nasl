# OpenVAS Vulnerability Test
# $Id: deb_3220.nasl 9355 2018-04-06 07:16:07Z cfischer $
# Auto-generated from advisory DSA 3220-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
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
    script_oid("1.3.6.1.4.1.25623.1.0.703220");
    script_version("$Revision: 9355 $");
    script_cve_id("CVE-2015-2806");
    script_name("Debian Security Advisory DSA 3220-1 (libtasn1-3 - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:16:07 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2015-04-11 00:00:00 +0200 (Sat, 11 Apr 2015)");
    script_tag(name: "cvss_base", value: "10.0");
    script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2015/dsa-3220.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "libtasn1-3 on Debian Linux");
    script_tag(name: "insight",   value: "Manage ASN1 (Abstract Syntax
Notation One) structures. The main features of this library are:

* on-line ASN1 structure management that doesn't require any C code
file generation.
* off-line ASN1 structure management with C code file generation
containing an array.
* DER (Distinguish Encoding Rules) encoding
* no limits for INTEGER and ENUMERATED values");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy),
this problem has been fixed in version 2.13-2+deb7u2.

We recommend that you upgrade your libtasn1-3 packages.");
    script_tag(name: "summary",   value: "Hanno Boeck discovered a stack-based
buffer overflow in the asn1_der_decoding function in Libtasn1, a library to manage
ASN.1 structures. A remote attacker could take advantage of this flaw to cause
an application using the Libtasn1 library to crash, or potentially to
execute arbitrary code.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libtasn1-3:amd64", ver:"2.13-2+deb7u2", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtasn1-3:i386", ver:"2.13-2+deb7u2", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtasn1-3-bin", ver:"2.13-2+deb7u2", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtasn1-3-dbg", ver:"2.13-2+deb7u2", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtasn1-3-dev", ver:"2.13-2+deb7u2", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
