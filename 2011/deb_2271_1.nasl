# OpenVAS Vulnerability Test
# $Id: deb_2271_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2271-1 (curl)
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
tag_insight = "Richard Silverman discovered that when doing GSSAPI authentication, libcurl
unconditionally performs credential delegation. This hands the server a copy of
the client's security credentials, allowing the server to impersonate the
client to any other using the same GSSAPI mechanism.
This is obviously a very sensitive operation, which should only be done when
the user explicitly so directs.


For the oldstable distribution (lenny), this problem has been fixed in
version 7.18.2-8lenny5.

For the stable distribution (squeeze), this problem has been fixed in
version 7.21.0-2.

For the testing distribution (wheezy), this problem has been fixed in
version 7.21.6-2.

For the unstable distribution (sid), this problem has been fixed in
version 7.21.6-2.

We recommend that you upgrade your curl packages.";
tag_summary = "The remote host is missing an update to curl
announced via advisory DSA 2271-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202271-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69972");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
 script_cve_id("CVE-2011-2192");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_name("Debian Security Advisory DSA 2271-1 (curl)");



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
if ((res = isdpkgvuln(pkg:"curl", ver:"7.18.2-8lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3", ver:"7.18.2-8lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.18.2-8lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.18.2-8lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.18.2-8lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.18.2-8lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"curl", ver:"7.21.0-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3", ver:"7.21.0-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.21.0-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.21.0-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.21.0-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.21.0-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"curl", ver:"7.21.6-3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3", ver:"7.21.6-3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.21.6-3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.21.6-3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.21.6-3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-gnutls-dev", ver:"7.21.6-3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-nss-dev", ver:"7.21.6-3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl4-openssl-dev", ver:"7.21.6-3", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
