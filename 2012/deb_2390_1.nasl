# OpenVAS Vulnerability Test
# $Id: deb_2390_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2390-1 (openssl)
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
tag_insight = "Several vulnerabilities were discovered in OpenSSL, an implementation
of TLS and related protocols.  The Common Vulnerabilities and
Exposures project identifies the following vulnerabilities:

CVE-2011-4108
The DTLS implementation performs a MAC check only if certain
padding is valid, which makes it easier for remote attackers
to recover plaintext via a padding oracle attack.

CVE-2011-4109
A double free vulnerability when X509_V_FLAG_POLICY_CHECK is
enabled, allows remote attackers to cause applications crashes
and potentially allow execution of arbitrary code by
triggering failure of a policy check.

CVE-2011-4354
On 32-bit systems, the operations on NIST elliptic curves
P-256 and P-384 are not correctly implemented, potentially
leaking the private ECC key of a TLS server.  (Regular
RSA-based keys are not affected by this vulnerability.)

CVE-2011-4576
The SSL 3.0 implementation does not properly initialize data
structures for block cipher padding, which might allow remote
attackers to obtain sensitive information by decrypting the
padding data sent by an SSL peer.

CVE-2011-4619
The Server Gated Cryptography (SGC) implementation in OpenSSL
does not properly handle handshake restarts, unnecessarily
simplifying CPU exhaustion attacks.

For the oldstable distribution (lenny), these problems have been fixed
in version 0.9.8g-15+lenny15.

For the stable distribution (squeeze), these problems have been fixed
in version 0.9.8o-4squeeze5.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 1.0.0f-1.

We recommend that you upgrade your openssl packages.";
tag_summary = "The remote host is missing an update to openssl
announced via advisory DSA 2390-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202390-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70708");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4354", "CVE-2011-4576", "CVE-2011-4619");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-11 03:28:14 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2390-1 (openssl)");


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
if((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8g-15+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8g-15+lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-15+lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8g-15+lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8g-15+lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8o-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8o-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8o-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8o-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"0.9.8o-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libcrypto1.0.0-udeb", ver:"1.0.0g-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl-dev", ver:"1.0.0g-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl-doc", ver:"1.0.0g-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.0g-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssl1.0.0-dbg", ver:"1.0.0g-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"openssl", ver:"1.0.0g-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
