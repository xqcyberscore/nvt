# OpenVAS Vulnerability Test
# $Id: deb_2276_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2276-1 (asterisk)
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
tag_insight = "Paul Belanger reported a vulnerability in Asterisk identified as AST-2011-008
(CVE-2011-2529) through which an unauthenticated attacker may crash an Asterisk
server remotely. A package containing a null char causes the SIP header parser
to alter unrelated memory structures.

Jared Mauch reported a vulnerability in Asterisk identified as AST-2011-009
through which an unauthenticated attacker may crash an Asterisk server remotely.
If a user sends a package with a Contact header with a missing left angle
bracket (<) the server will crash. A possible workaround is to disable chan_sip.

The vulnerability identified as AST-2011-010 (CVE-2011-2535) reported about an
input validation error in the IAX2 channel driver. An unauthenticated attacker
may crash an Asterisk server remotely by sending a crafted option control frame.


For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.21.2~dfsg-3+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.2.9-2+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in
version 1:1.8.4.3-1.

For the unstable distribution (sid), this problem has been fixed in
version 1:1.8.4.3-1.

We recommend that you upgrade your asterisk packages.";
tag_summary = "The remote host is missing an update to asterisk
announced via advisory DSA 2276-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202276-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69982");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
 script_cve_id("CVE-2011-2529", "CVE-2011-2535");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 2276-1 (asterisk)");



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
if ((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.4.21.2~dfsg-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.4.21.2~dfsg-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.4.21.2~dfsg-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.4.21.2~dfsg-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.4.21.2~dfsg-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1:1.4.21.2~dfsg-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1:1.4.21.2~dfsg-3+lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.6.2.9-2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.6.2.9-2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.6.2.9-2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.6.2.9-2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.6.2.9-2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1:1.6.2.9-2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1:1.6.2.9-2+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-modules", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1:1.8.4.4~dfsg-2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
