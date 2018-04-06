# OpenVAS Vulnerability Test
# $Id: deb_2621.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2621-1 using nvtgen 1.0
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

tag_affected  = "openssl on Debian Linux";
tag_insight   = "This package contains the openssl binary and related tools.";
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed in
version 0.9.8o-4squeeze14.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.1e-1.

We recommend that you upgrade your openssl packages.";
tag_summary   = "Multiple vulnerabilities have been found in OpenSSL. The Common
Vulnerabilities and Exposures project identifies the following issues:

CVE-2013-0166 
OpenSSL does not properly perform signature verification for OCSP
responses, which allows remote attackers to cause a denial of
service via an invalid key.

CVE-2013-0169A timing side channel attack has been found in CBC padding
allowing an attacker to recover pieces of plaintext via statistical
analysis of crafted packages, known as the Lucky Thirteen 
issue.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892621");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-0169", "CVE-2013-0166");
    script_name("Debian Security Advisory DSA 2621-1 (openssl - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-02-13 00:00:00 +0100 (Wed, 13 Feb 2013)");
    script_tag(name: "cvss_base", value:"5.0");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2621.html");


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
if ((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8o-4squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8o-4squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-4squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8o-4squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-4squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
