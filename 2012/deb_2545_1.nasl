# OpenVAS Vulnerability Test
# $Id: deb_2545_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2545-1 (qemu)
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
tag_insight = "Multiple vulnerabilities have been discovered in qemu, a fast processor
emulator. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2012-2652:

The snapshot mode of QEMU (-snapshot) incorrectly handles temporary
files used to store the current state, making it vulnerable to
symlink attacks (including arbitrary file overwriting and guest
information disclosure) due to a race condition.

CVE-2012-3515:

QEMU does not properly handle VT100 escape sequences when emulating
certain devices with a virtual console backend. An attacker within a
guest with access to the vulnerable virtual console could overwrite
memory of QEMU and escalate privileges to that of the qemu process.

For the stable distribution (squeeze), these problems have been fixed in
version 0.12.5+dfsg-3squeeze2.

For the testing distribution (wheezy), and the unstable distribution
(sid), these problems will been fixed soon.

We recommend that you upgrade your qemu packages.";
tag_summary = "The remote host is missing an update to qemu
announced via advisory DSA 2545-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202545-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72174");
 script_tag(name:"cvss_base", value:"7.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-2652", "CVE-2012-3515");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-09-15 04:24:19 -0400 (Sat, 15 Sep 2012)");
 script_name("Debian Security Advisory DSA 2545-1 (qemu)");



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
if((res = isdpkgvuln(pkg:"libqemu-dev", ver:"0.12.5+dfsg-3squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"qemu", ver:"0.12.5+dfsg-3squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"qemu-keymaps", ver:"0.12.5+dfsg-3squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system", ver:"0.12.5+dfsg-3squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user", ver:"0.12.5+dfsg-3squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user-static", ver:"0.12.5+dfsg-3squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"qemu-utils", ver:"0.12.5+dfsg-3squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
