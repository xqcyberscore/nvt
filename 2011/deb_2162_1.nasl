# OpenVAS Vulnerability Test
# $Id: deb_2162_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2162-1 (openssl)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Neel Mehta discovered that an incorrectly formatted ClientHello handshake
message could cause OpenSSL to parse past the end of the message.  This
allows an attacker to crash an application using OpenSSL by triggering
an invalid memory access.  Additionally, some applications may be vulnerable
to expose contents of a parsed OCSP nonce extension.

Packages in the oldstable distribution (lenny) are not affected by this
problem.

For the stable distribution (squeeze), this problem has been fixed in
version 0.9.8o-4squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 0.9.8o-5.

For the unstable distribution (sid), this problem has been fixed in
version 0.9.8o-5.

We recommend that you upgrade your invalid memory access packages.";
tag_summary = "The remote host is missing an update to openssl
announced via advisory DSA 2162-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202162-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68997");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2011-0014");
 script_name("Debian Security Advisory DSA 2162-1 (openssl)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8o-4squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8o-4squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-4squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8o-4squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-4squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8o-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8o-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8o-5", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-5", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
