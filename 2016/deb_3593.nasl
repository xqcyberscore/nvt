# OpenVAS Vulnerability Test
# $Id: deb_3593.nasl 8154 2017-12-18 07:30:14Z teissa $
# Auto-generated from advisory DSA 3593-1 using nvtgen 1.0
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
    script_oid("1.3.6.1.4.1.25623.1.0.703593");
    script_version("$Revision: 8154 $");
    script_cve_id("CVE-2015-8806", "CVE-2016-1762", "CVE-2016-1833", "CVE-2016-1834",
                  "CVE-2016-1835", "CVE-2016-1836", "CVE-2016-1837", "CVE-2016-1838",
                  "CVE-2016-1839", "CVE-2016-1840", "CVE-2016-2073", "CVE-2016-3627",
                  "CVE-2016-3705", "CVE-2016-4447", "CVE-2016-4449", "CVE-2016-4483");
    script_name("Debian Security Advisory DSA 3593-1 (libxml2 - security update)");
    script_tag(name: "last_modification", value: "$Date: 2017-12-18 08:30:14 +0100 (Mon, 18 Dec 2017) $");
    script_tag(name: "creation_date", value: "2016-06-02 00:00:00 +0200 (Thu, 02 Jun 2016)");
    script_tag(name: "cvss_base", value: "10.0");
    script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name: "solution_type", value: "VendorFix");
    script_tag(name: "qod_type", value: "package");

    script_xref(name: "URL", value: "http://www.debian.org/security/2016/dsa-3593.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "libxml2 on Debian Linux");
    script_tag(name: "insight",   value: "XML is a metalanguage to let you design
your own markup language. A regular markup language defines a way to describe
information in a certain class of documents (eg HTML). XML lets you define your
own customized markup languages for many classes of document. It
can do this because it's written in SGML, the international standard
metalanguage for markup languages.");
    script_tag(name: "solution",  value: "For the stable distribution (jessie),
these problems have been fixed in version 2.9.1+dfsg1-5+deb8u2.

We recommend that you upgrade your libxml2 packages.");
    script_tag(name: "summary",   value: "Several vulnerabilities were discovered
in libxml2, a library providing support to read, modify and write XML and HTML
files. A remote attacker could provide a specially crafted XML or HTML file that,
when processed by an application using libxml2, would cause a denial-of-service
against the application, or potentially the execution of arbitrary code with the
privileges of the user running the application.");
    script_tag(name: "vuldetect", value: "This check tests the installed software
version using the apt package manager.");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"libxml2:amd64", ver:"2.9.1+dfsg1-5+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxml2:i386", ver:"2.9.1+dfsg1-5+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxml2-dbg:amd64", ver:"2.9.1+dfsg1-5+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxml2-dbg:i386", ver:"2.9.1+dfsg1-5+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"libxml2-dev:amd64", ver:"2.9.1+dfsg1-5+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxml2-dev:i386", ver:"2.9.1+dfsg1-5+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if ((res = isdpkgvuln(pkg:"libxml2-doc", ver:"2.9.1+dfsg1-5+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.9.1+dfsg1-5+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libxml2-utils-dbg", ver:"2.9.1+dfsg1-5+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-libxml2", ver:"2.9.1+dfsg1-5+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-libxml2-dbg", ver:"2.9.1+dfsg1-5+deb8u2", rls_regex:"DEB8.[0-9]+")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
