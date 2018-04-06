# OpenVAS Vulnerability Test
# $Id: deb_2866.nasl 9354 2018-04-06 07:15:32Z cfischer $
# Auto-generated from advisory DSA 2866-1 using nvtgen 1.0
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

tag_affected  = "gnutls26 on Debian Linux";
tag_insight   = "gnutls is a portable library which implements the Transport Layer
Security (TLS) 1.0 and Secure Sockets Layer (SSL) 3.0 protocols.";
tag_solution  = "For the stable distribution (wheezy), this problem has been fixed in
version 2.12.20-8.

For the testing distribution (jessie) and the unstable distribution
(sid), this problem has been fixed in version 2.12.23-12.

We recommend that you upgrade your gnutls26 packages.";
tag_summary   = "Suman Jana reported that GnuTLS, deviating from the documented behavior,
considers a version 1 intermediate certificate as a CA certificate by
default.

The oldstable distribution (squeeze) is not affected by this problem as
X.509 version 1 trusted CA certificates are not allowed by default.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.702866");
    script_version("$Revision: 9354 $");
    script_cve_id("CVE-2014-1959");
    script_name("Debian Security Advisory DSA 2866-1 (gnutls26 - certificate verification flaw)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2014-02-22 00:00:00 +0100 (Sat, 22 Feb 2014)");
    script_tag(name:"cvss_base", value:"5.8");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

    script_xref(name: "URL", value: "http://www.debian.org/security/2014/dsa-2866.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
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

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.12.20-8", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls26-doc", ver:"2.12.20-8", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"guile-gnutls", ver:"2.12.20-8", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.12.20-8", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-openssl27", ver:"2.12.20-8", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26", ver:"2.12.20-8", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.12.20-8", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutlsxx27", ver:"2.12.20-8", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.12.20-8", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls26-doc", ver:"2.12.20-8", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"guile-gnutls", ver:"2.12.20-8", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.12.20-8", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-openssl27", ver:"2.12.20-8", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26", ver:"2.12.20-8", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.12.20-8", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutlsxx27", ver:"2.12.20-8", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.12.20-8", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls26-doc", ver:"2.12.20-8", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"guile-gnutls", ver:"2.12.20-8", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.12.20-8", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-openssl27", ver:"2.12.20-8", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26", ver:"2.12.20-8", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.12.20-8", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutlsxx27", ver:"2.12.20-8", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls-bin", ver:"2.12.20-8", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gnutls26-doc", ver:"2.12.20-8", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"guile-gnutls", ver:"2.12.20-8", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-dev", ver:"2.12.20-8", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls-openssl27", ver:"2.12.20-8", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26", ver:"2.12.20-8", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutls26-dbg", ver:"2.12.20-8", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libgnutlsxx27", ver:"2.12.20-8", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
