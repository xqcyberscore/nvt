# OpenVAS Vulnerability Test
# $Id: deb_2498_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2498-1 (dhcpcd)
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
tag_insight = "It was discovered that dhcpcd, a DHCP client, was vulnerable to a stack
overflow. A malformed DHCP message could crash the client, causing a denial of
service, and potentially remote code execution through properly designed
malicous DHCP packets.

For the stable distribution (squeeze), this problem has been fixed in
version 1:3.2.3-5+squeeze1.

For the testing distribution (wheezy), this problem has been fixed in
version 1:3.2.3-11.

For the unstable distribution (sid), this problem has been fixed in
version 1:3.2.3-11.

We recommend that you upgrade your dhcpcd package.";
tag_summary = "The remote host is missing an update to dhcpcd
announced via advisory DSA 2498-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202498-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71481");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-2152");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:07:13 -0400 (Fri, 10 Aug 2012)");
 script_name("Debian Security Advisory DSA 2498-1 (dhcpcd)");



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
if((res = isdpkgvuln(pkg:"dhcpcd", ver:"1:3.2.3-5+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"dhcpcd", ver:"1:3.2.3-11", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
