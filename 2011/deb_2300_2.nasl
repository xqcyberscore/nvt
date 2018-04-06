# OpenVAS Vulnerability Test
# $Id: deb_2300_2.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2300-2 (nss)
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
tag_insight = "Several unauthorised SSL certificates have been found in the wild issued
for the DigiNotar Certificate Authority, obtained through a security
compromise with said company. Debian, like other software
distributors, has as a precaution decided to disable the DigiNotar
Root CA by default in the NSS crypto libraries.

As a result from further understanding of the incident, this update
to DSA 2300 disables additional DigiNotar issuing certificates.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.12.3.1-0lenny6.

For the stable distribution (squeeze), this problem has been fixed in
version 3.12.8-1+squeeze3.

For the unstable distribution (sid), this problem has been fixed in
version 3.12.11-2.

We recommend that you upgrade your nss packages.";
tag_summary = "The remote host is missing an update to nss
announced via advisory DSA 2300-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202300-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70236");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 2300-2 (nss)");



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
if ((res = isdpkgvuln(pkg:"libnss3-1d", ver:"3.12.3.1-0lenny6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-1d-dbg", ver:"3.12.3.1-0lenny6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-dev", ver:"3.12.3.1-0lenny6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-tools", ver:"3.12.3.1-0lenny6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-1d", ver:"3.12.8-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-1d-dbg", ver:"3.12.8-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-dev", ver:"3.12.8-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libnss3-tools", ver:"3.12.8-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
