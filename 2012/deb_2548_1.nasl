# OpenVAS Vulnerability Test
# $Id: deb_2548_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2548-1 (tor)
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
tag_insight = "Severel vulnerabilities have been discovered in Tor, an online privacy
tool.

CVE-2012-3518

Avoid an uninitialised memory read when reading a vote or consensus
document that has an unrecognized flavour name. This could lead to
a remote, resulting in denial of service.

CVE-2012-3519

Try to leak less information about what relays a client is choosing to
a side-channel attacker.

CVE-2012-4419

By providing specially crafted date strings to a victim tor instance,
an attacker can cause it to run into an assertion and shut down

Additionally the update to stable includes the following fixes:
- - When waiting for a client to renegotiate, don't allow it to add any
bytes to the input buffer. This fixes a potential DoS issue
[tor-5934, tor-6007].

For the stable distribution (squeeze), these problems have been fixed in
version 0.2.2.39-1.

For the unstable distribution, these problems have been fixed in version
0.2.3.22-rc-1.

We recommend that you upgrade your tor packages.";
tag_summary = "The remote host is missing an update to tor
announced via advisory DSA 2548-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202548-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72177");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2012-3518", "CVE-2012-3519", "CVE-2012-4419");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-09-15 04:24:59 -0400 (Sat, 15 Sep 2012)");
 script_name("Debian Security Advisory DSA 2548-1 (tor)");



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
if((res = isdpkgvuln(pkg:"tor", ver:"0.2.2.39-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"tor-dbg", ver:"0.2.2.39-1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"tor-geoipdb", ver:"0.2.2.39-1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
