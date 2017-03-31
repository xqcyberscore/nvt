# OpenVAS Vulnerability Test
# $Id: deb_2289_1.nasl 5413 2017-02-24 08:22:28Z teissa $
# Description: Auto-generated from advisory DSA 2289-1 (typo3-src)
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
tag_insight = "Several remote vulnerabilities have been discovered in the TYPO3 web
content management framework: cross-site scripting, information
disclosure, authentication delay bypass, and arbitrary file deletion.
More details can be found in the Typo3 security advisory:
http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2011
- -001/

For the oldstable distribution (lenny), these problems have been fixed in
version 4.2.5-1+lenny8.

For the stable distribution (squeeze), these problems have been fixed in
version 4.3.9+dfsg1-1+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 4.5.4+dfsg1-1.

We recommend that you upgrade your typo3-src packages.";
tag_summary = "The remote host is missing an update to typo3-src
announced via advisory DSA 2289-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202289-1";


if(description)
{
 script_id(70225);
 script_version("$Revision: 5413 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-24 09:22:28 +0100 (Fri, 24 Feb 2017) $");
 script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 2289-1 (typo3-src)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
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
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.2.5-1+lenny8", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.2", ver:"4.2.5-1+lenny8", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.3.9+dfsg1-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-database", ver:"4.3.9+dfsg1-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.3", ver:"4.3.9+dfsg1-1+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3", ver:"4.5.4+dfsg1-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-database", ver:"4.5.4+dfsg1-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-dummy", ver:"4.5.4+dfsg1-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"typo3-src-4.5", ver:"4.5.4+dfsg1-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
