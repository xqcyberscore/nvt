# OpenVAS Vulnerability Test
# $Id: deb_2258_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2258-1 (kolab-cyrus-imapd)
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
tag_insight = "It was discovered that the STARTTLS implementation of the
Kolab Cyrus IMAP server does not properly restrict I/O buffering,
which allows man-in-the-middle attackers to insert commands into encrypted
IMAP, LMTP, NNTP and POP3 sessions by sending a cleartext command that is
processed after TLS is in place.


For the oldstable distribution (lenny), this problem has been fixed in
version 2.2.13-5+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 2.2.13-9.1.

For the testing distribution (wheezy), this problem has been fixed in
version 2.2.13p1-0.1.

For the unstable distribution (sid), this problem has been fixed in
version 2.2.13p1-0.1.

We recommend that you upgrade your kolab-cyrus-imapd packages.";
tag_summary = "The remote host is missing an update to kolab-cyrus-imapd
announced via advisory DSA 2258-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202258-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69965");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-1926");
 script_name("Debian Security Advisory DSA 2258-1 (kolab-cyrus-imapd)");



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
if ((res = isdpkgvuln(pkg:"kolab-cyrus-admin", ver:"2.2.13-5+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-clients", ver:"2.2.13-5+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-common", ver:"2.2.13-5+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-imapd", ver:"2.2.13-5+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-pop3d", ver:"2.2.13-5+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-libcyrus-imap-perl", ver:"2.2.13-5+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-admin", ver:"2.2.13-9.1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-clients", ver:"2.2.13-9.1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-common", ver:"2.2.13-9.1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-imapd", ver:"2.2.13-9.1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-pop3d", ver:"2.2.13-9.1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-libcyrus-imap-perl", ver:"2.2.13-9.1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-admin", ver:"2.2.13p1-0.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-clients", ver:"2.2.13p1-0.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-common", ver:"2.2.13p1-0.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-imapd", ver:"2.2.13p1-0.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-cyrus-pop3d", ver:"2.2.13p1-0.3", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kolab-libcyrus-imap-perl", ver:"2.2.13p1-0.3", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
