# OpenVAS Vulnerability Test
# $Id: deb_2454_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2454-1 (openssl)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
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
tag_insight = "Multiple vulnerabilities have been found in OpenSSL. The Common
Vulnerabilities and Exposures project identifies the following issues:

CVE-2012-0884

Ivan Nestlerode discovered a weakness in the CMS and PKCS #7
implementations that could allow an attacker to decrypt data
via a Million Message Attack (MMA).

CVE-2012-1165

It was discovered that a NULL pointer could be dereferenced
when parsing certain S/MIME messages, leading to denial of
service.

CVE-2012-2110

Tavis Ormandy, Google Security Team, discovered a vulnerability
in the way DER-encoded ASN.1 data is parsed that can result in
a heap overflow.


Additionally, the fix for CVE-2011-4619 has been updated to address an
issue with SGC handshakes.

For the stable distribution (squeeze), these problems have been fixed in
version 0.9.8o-4squeeze11.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.1a-1.

We recommend that you upgrade your openssl packages.";
tag_summary = "The remote host is missing an update to openssl
announced via advisory DSA 2454-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202454-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71259");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-0884", "CVE-2012-1165", "CVE-2012-2110", "CVE-2011-4619");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-04-30 07:57:50 -0400 (Mon, 30 Apr 2012)");
 script_name("Debian Security Advisory DSA 2454-1 (openssl)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");
res = "";
report = "";
if((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8o-4squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8o-4squeeze12", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-4squeeze12", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8o-4squeeze12", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-4squeeze12", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
