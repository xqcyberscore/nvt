# OpenVAS Vulnerability Test
# $Id: deb_2488_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2488-1 (iceweasel)
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
tag_insight = "Several vulnerabilities have been discovered in Iceweasel, a web
browser based on Firefox. The included XULRunner library provides
rendering services for several other applications included in Debian.

CVE-2012-1937

Mozilla developers discovered several memory corruption bugs,
which may lead to the execution of arbitrary code.

CVE-2012-1940

Abhishek Arya discovered a use-after-free problem when working
with column layout with absolute positioning in a container that
changes size, which may lead to the execution of arbitrary code.

CVE-2012-1947

Abhishek Arya discovered a heap buffer overflow in utf16 to latin1
character set conersion, allowing to execute arbitray code.


Note: We'd like to advise users of Iceweasel's 3.5 branch in Debian
stable to consider to upgrade to the Iceweasel 10.0 ESR (Extended
Support Release) which is now available in Debian Backports.
Although Debian will continue to support Iceweasel 3.5 in stable with
security updates, this can only be done on a best effort base as
upstream provides no such support anymore. On top of that, the 10.0
branch adds proactive security features to the browser.

For the stable distribution (squeeze), this problem has been fixed in
version 3.5.16-16.

For the unstable distribution (sid), this problem has been fixed in
version 10.0.5esr-1.

We recommend that you upgrade your iceweasel packages.";
tag_summary = "The remote host is missing an update to iceweasel
announced via advisory DSA 2488-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202488-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71468");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-1937", "CVE-2012-1940", "CVE-2012-1947");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:02:38 -0400 (Fri, 10 Aug 2012)");
 script_name("Debian Security Advisory DSA 2488-1 (iceweasel)");



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
if((res = isdpkgvuln(pkg:"iceweasel", ver:"3.5.16-17", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"3.5.16-17", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.9.1.16-17", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libmozjs2d", ver:"1.9.1.16-17", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libmozjs2d-dbg", ver:"1.9.1.16-17", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.9.1.16-17", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"xulrunner-1.9.1", ver:"1.9.1.16-17", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"xulrunner-1.9.1-dbg", ver:"1.9.1.16-17", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"xulrunner-dev", ver:"1.9.1.16-17", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
