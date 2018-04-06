# OpenVAS Vulnerability Test
# $Id: deb_2309_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2309-1 (openssl)
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
tag_insight = "Several fraudulent SSL certificates have been found in the wild issued
by the DigiNotar Certificate Authority, obtained through a security
compromise of said company. After further updates on this incident, it
has been determined that all of DigiNotar's signing certificates can no
longer be trusted.
Debian, like other software distributors and vendors, has decided to
distrust all of DigiNotar's CAs. In this update, this is done in the
crypto library (a component of the OpenSSL toolkit) by marking such
certificates as revoked.
Any application that uses said component should now reject certificates
signed by DigiNotar. Individual applications may allow users to overrride
the validation failure. However, making exceptions is highly
discouraged and should be carefully verified.

Additionally, a vulnerability has been found in the ECDHE_ECDS cipher
where timing attacks make it easier to determine private keys. The
Common Vulnerabilities and Exposures project identifies it as
CVE-2011-1945.

For the oldstable distribution (lenny), these problems have been fixed in
version 0.9.8g-15+lenny12.

For the stable distribution (squeeze), these problems have been fixed in
version 0.9.8o-4squeeze2.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.0.0e-1.

We recommend that you upgrade your openssl packages.";
tag_summary = "The remote host is missing an update to openssl
announced via advisory DSA 2309-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202309-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70243");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2011-1945");
 script_name("Debian Security Advisory DSA 2309-1 (openssl)");



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
if ((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8g-15+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8g-15+lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-15+lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8g-15+lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8g-15+lenny12", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8o-4squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8o-4squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-4squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8o-4squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-4squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
