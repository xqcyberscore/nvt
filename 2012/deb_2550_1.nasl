# OpenVAS Vulnerability Test
# $Id: deb_2550_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2550-1 (asterisk)
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
tag_insight = "Several vulnerabilities were discovered in Asterisk, a PBX and telephony
toolkit, allowing privilege escalation in the Asterisk Manager, denial of
service or privilege escalation.

More detailed information can be found in the Asterisk advisories:
http://downloads.asterisk.org/pub/security/AST-2012-010.html
http://downloads.asterisk.org/pub/security/AST-2012-011.html
http://downloads.asterisk.org/pub/security/AST-2012-012.html
http://downloads.asterisk.org/pub/security/AST-2012-013.html

For the stable distribution (squeeze), these problems have been fixed in
version 1:1.6.2.9-2+squeeze7.

For the testing distribution (wheezy) and the unstable distribution (sid),
these problems have been fixed in version 1:1.8.13.1~dfsg-1.

We recommend that you upgrade your asterisk packages.";
tag_summary = "The remote host is missing an update to asterisk
announced via advisory DSA 2550-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202550-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72408");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_cve_id("CVE-2012-2186", "CVE-2012-3812", "CVE-2012-3863", "CVE-2012-4737");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-09-23 02:15:34 -0400 (Sun, 23 Sep 2012)");
 script_name("Debian Security Advisory DSA 2550-1 (asterisk)");



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
if((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.6.2.9-2+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.6.2.9-2+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.6.2.9-2+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.6.2.9-2+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.6.2.9-2+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1:1.6.2.9-2+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1:1.6.2.9-2+squeeze7", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-modules", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1:1.8.13.1~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
