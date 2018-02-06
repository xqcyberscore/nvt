# OpenVAS Vulnerability Test
# $Id: deb_2483_1.nasl 8671 2018-02-05 16:38:48Z teissa $
# Description: Auto-generated from advisory DSA 2483-1 (strongswan)
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
tag_insight = "An authentication bypass issue was discovered by the Codenomicon CROSS
project in strongSwan, an IPsec-based VPN solution. When using
RSA-based setups, a missing check in the gmp plugin could allow an
attacker presenting a forged signature to successfully authenticate
against a strongSwan responder.

The default configuration in Debian does not use the gmp plugin for
RSA operations but rather the OpenSSL plugin, so the packages as
shipped by Debian are not vulnerable.

For the stable distribution (squeeze), this problem has been fixed in
version 4.4.1-5.2.

For the testing distribution (wheezy), this problem has been fixed in
version 4.5.2-1.4.

For the unstable distribution (sid), this problem has been fixed in
version 4.5.2-1.4.

We recommend that you upgrade your strongswan packages.";
tag_summary = "The remote host is missing an update to strongswan
announced via advisory DSA 2483-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202483-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71360");
 script_cve_id("CVE-2012-2388");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 8671 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
 script_tag(name:"creation_date", value:"2012-05-31 11:52:39 -0400 (Thu, 31 May 2012)");
 script_name("Debian Security Advisory DSA 2483-1 (strongswan)");



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
if((res = isdpkgvuln(pkg:"libstrongswan", ver:"4.4.1-5.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan", ver:"4.4.1-5.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-dbg", ver:"4.4.1-5.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev1", ver:"4.4.1-5.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev2", ver:"4.4.1-5.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-nm", ver:"4.4.1-5.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-starter", ver:"4.4.1-5.2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libstrongswan", ver:"4.5.2-1.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan", ver:"4.5.2-1.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-dbg", ver:"4.5.2-1.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev1", ver:"4.5.2-1.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-ikev2", ver:"4.5.2-1.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-nm", ver:"4.5.2-1.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"strongswan-starter", ver:"4.5.2-1.3", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
