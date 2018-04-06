# OpenVAS Vulnerability Test
# $Id: deb_2622.nasl 9353 2018-04-06 07:14:20Z cfischer $
# Auto-generated from advisory DSA 2622-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013-2014 Greenbone Networks GmbH http://greenbone.net
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

tag_affected  = "polarssl on Debian Linux";
tag_insight   = "PolarSSL is a fork of the abandoned project XySSL. It is a lean crypto
library providing SSL and TLS support in your programs.";
tag_solution  = "For the stable distribution (squeeze), these problems have been fixed in
version 0.12.1-1squeeze1.

For the testing distribution (wheezy), and the unstable distribution
(sid), these problems have been fixed in version 1.1.4-2.

We recommend that you upgrade your polarssl packages.";
tag_summary   = "Multiple vulnerabilities have been found in PolarSSL. The Common
Vulnerabilities and Exposures project identifies the following issues:

CVE-2013-0169A timing side channel attack has been found in CBC padding
allowing an attacker to recover pieces of plaintext via statistical
analysis of crafted packages, known as the Lucky Thirteen 
issue.

CVE-2013-1621 
An array index error might allow remote attackers to cause a denial
of service via vectors involving a crafted padding-length value
during validation of CBC padding in a TLS session.

CVE-2013-1622 
Malformed CBC data in a TLS session could allow remote attackers to
conduct distinguishing attacks via statistical analysis of timing
side-channel data for crafted packets.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.892622");
    script_version("$Revision: 9353 $");
    script_cve_id("CVE-2013-0169", "CVE-2013-1621", "CVE-2013-1622");
    script_name("Debian Security Advisory DSA 2622-1 (polarssl - several vulnerabilities)");
    script_tag(name: "last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value:"2013-02-13 00:00:00 +0100 (Wed, 13 Feb 2013)");
    script_tag(name:"cvss_base", value:"10.0");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2622.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013-2014 Greenbone Networks GmbH http://greenbone.net");
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
if ((res = isdpkgvuln(pkg:"libpolarssl-dev", ver:"0.12.1-1squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl-runtime", ver:"0.12.1-1squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl0", ver:"0.12.1-1squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl-dev", ver:"1.1.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl-runtime", ver:"1.1.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl0", ver:"1.1.4-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl-dev", ver:"1.1.4-2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl-runtime", ver:"1.1.4-2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl0", ver:"1.1.4-2", rls:"DEB7.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl-dev", ver:"1.1.4-2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl-runtime", ver:"1.1.4-2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl0", ver:"1.1.4-2", rls:"DEB7.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl-dev", ver:"1.1.4-2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl-runtime", ver:"1.1.4-2", rls:"DEB7.3")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpolarssl0", ver:"1.1.4-2", rls:"DEB7.3")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
