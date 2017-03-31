# OpenVAS Vulnerability Test
# $Id: deb_216_1.nasl 3939 2016-09-02 05:15:43Z teissa $
# Description: Auto-generated from advisory DSA 216-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "Stefan Esser of e-matters discovered a buffer overflow in fetchmail,
an SSL enabled POP3, APOP and IMAP mail gatherer/forwarder.  When
fetchmail retrieves a mail all headers that contain addresses are
searched for local addresses.  If a hostname is missing, fetchmail
appends it but doesn't reserve enough space for it.  This heap
overflow can be used by remote attackers to crash it or to execute
arbitrary code with the privileges of the user running fetchmail.

For the current stable distribution (woody) this problem has been
fixed in version 5.9.11-6.2 of fetchmail and fetchmail-ssl.

For the old stable distribution (potato) this problem has been fixed
in version 5.3.3-4.3.

For the current unstable distribution (sid) this problem has been
fixed in version 6.2.0-1 of fetchmail and fetchmail-ssl.

We recommend that you upgrade your fetchmail packages.";
tag_summary = "The remote host is missing an update to fetchmail
announced via advisory DSA 216-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20216-1";

if(description)
{
 script_id(53455);
 script_version("$Revision: 3939 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-02 07:15:43 +0200 (Fri, 02 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-1365");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Debian Security Advisory DSA 216-1 (fetchmail)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"fetchmailconf", ver:"5.3.3-4.3", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fetchmail", ver:"5.3.3-4.3", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fetchmail-common", ver:"5.9.11-6.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fetchmailconf", ver:"5.9.11-6.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fetchmail", ver:"5.9.11-6.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"fetchmail-ssl", ver:"5.9.11-6.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
