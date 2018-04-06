# OpenVAS Vulnerability Test
# $Id: deb_2225_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2225-1 (asterisk)
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
tag_insight = "Several vulnerabilities have been discovered in Asterisk, an Open Source
PBX and telephony toolkit.

CVE-2011-1147

Matthew Nicholson discovered that incorrect handling of UDPTL packets
may lead to denial of service of the execution of arbitrary code.

CVE-2011-1174

Blake Cornell discovered that incorrect connection handling in the
manager interface may lead to denial of service.

CVE-2011-1175

Blake Cornell and Chris May discovered that incorrect TCP connection
handling may lead to denial of service.

CVE-2011-1507

Tzafrir Cohen discovered that insufficient limitation of connection
requests in several TCP based services may lead to denial of service.
Please see http://downloads.asterisk.org/pub/security/AST-2011-005.html
for details.

CVE-2011-1599

Matthew Nicholson discovered a privilege escalation vulnerability in
the manager interface.

For the oldstable distribution (lenny), this problem has been fixed in
version 1:1.4.21.2~dfsg-3+lenny2.1.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.6.2.9-2+squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 1:1.8.3.3-1.

We recommend that you upgrade your asterisk packages.";
tag_summary = "The remote host is missing an update to asterisk
announced via advisory DSA 2225-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202225-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69568");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_cve_id("CVE-2011-1147", "CVE-2011-1174", "CVE-2011-1175", "CVE-2011-1507", "CVE-2011-1599");
 script_name("Debian Security Advisory DSA 2225-1 (asterisk)");



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
if ((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.4.21.2~dfsg-3+lenny2.1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.4.21.2~dfsg-3+lenny2.1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.4.21.2~dfsg-3+lenny2.1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.4.21.2~dfsg-3+lenny2.1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.4.21.2~dfsg-3+lenny2.1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1:1.4.21.2~dfsg-3+lenny2.1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1:1.4.21.2~dfsg-3+lenny2.1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.6.2.9-2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.6.2.9-2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.6.2.9-2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.6.2.9-2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.6.2.9-2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1:1.6.2.9-2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1:1.6.2.9-2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
