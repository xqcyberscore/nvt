# OpenVAS Vulnerability Test
# $Id: deb_2518_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2518-1 (krb5)
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
tag_insight = "Emmanuel Bouillon from NCI Agency discovered multiple vulnerabilities in MIT
Kerberos, a daemon implementing the network authentication protocol.

CVE-2012-1014

By sending specially crafted AS-REQ (Authentication Service Request) to a KDC
(Key Distribution Center), an attacker could make it free an uninitialized
pointer, corrupting the heap.  This can lead to process crash or even arbitrary
code execution.
.
This CVE only affects testing (wheezy) and unstable (sid) distributions.

CVE-2012-1015

By sending specially crafted AS-REQ to a KDC, an attacker could make it
dereference an uninitialized pointer, leading to process crash or even
arbitrary code execution

In both cases, arbitrary code execution is believed to be difficult to achieve,
but might not be impossible.

For the stable distribution (squeeze), this problem has been fixed in
version 1.8.3+dfsg-4squeeze6.

For the testing distribution (wheezy), this problem has been fixed in
version 1.10.1+dfsg-2.

For the unstable distribution (sid), this problem has been fixed in
version 1.10.1+dfsg-2.

We recommend that you upgrade your krb5 packages.";
tag_summary = "The remote host is missing an update to krb5
announced via advisory DSA 2518-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202518-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71495");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-1014", "CVE-2012-1015");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:15:01 -0400 (Fri, 10 Aug 2012)");
 script_name("Debian Security Advisory DSA 2518-1 (krb5)");



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
if((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-user", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt-mit7", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv-mit7", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkdb5-4", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb53", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.8.3+dfsg-4squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-gss-samples", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-locales", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-user", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt-mit8", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv-mit8", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkdb5-6", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.10.1+dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
