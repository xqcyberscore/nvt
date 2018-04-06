# OpenVAS Vulnerability Test
# $Id: deb_2493_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2493-1 (asterisk)
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
tag_insight = "Several vulnerabilities were discovered in Asterisk, a PBX and
telephony toolkit.

CVE-2012-2947
The IAX2 channel driver allows remote attackers to cause a
denial of service (daemon crash) by placing a call on hold
(when a certain mohinterpret setting is enabled).

CVE-2012-2948
The Skinny channel driver allows remote authenticated users to
cause a denial of service (NULL pointer dereference and daemon
crash) by closing a connection in off-hook mode.

In addition, it was discovered that Asterisk does not set the
alwaysauthreject option by default in the SIP channel driver.  This
allows remote attackers to observe a difference in response behavior
and check for the presence of account names.  (CVE-2011-2666)  System
administrators concerned by this user enumerating vulnerability should
enable the alwaysauthreject option in the configuration.  We do not
plan to change the default setting in the stable version
(Asterisk 1.6) in order to preserve backwards compatibility.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.6.2.9-2+squeeze6.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 1:1.8.13.0~dfsg-1.

We recommend that you upgrade your asterisk packages.";
tag_summary = "The remote host is missing an update to asterisk
announced via advisory DSA 2493-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202493-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71471");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2012-2947", "CVE-2012-2948", "CVE-2011-2666");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:05:29 -0400 (Fri, 10 Aug 2012)");
 script_name("Debian Security Advisory DSA 2493-1 (asterisk)");



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
if((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.6.2.9-2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.6.2.9-2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.6.2.9-2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.6.2.9-2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.6.2.9-2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1:1.6.2.9-2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1:1.6.2.9-2+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-modules", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1:1.8.13.0~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
