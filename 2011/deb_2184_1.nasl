# OpenVAS Vulnerability Test
# $Id: deb_2184_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2184-1 (isc-dhcp)
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
tag_solution = "The oldstable distribution (lenny) is not affected by this problem.

For the stable distribution (squeeze), this problem has been fixed in
version 4.1.1-P1-15+squeeze1.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem has been fixed in version 4.1.1-P1-16.

We recommend that you upgrade your isc-dhcp packages.

https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202184-1";

tag_insight = "It was discovered that the ISC DHCPv6 server does not correctly
process requests which come from unexpected source addresses, leading
to an assertion failure and a daemon crash.";
tag_summary = "The remote host is missing an update to isc-dhcp
announced via advisory DSA 2184-1.";




if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69119");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2011-0413");
 script_name("Debian Security Advisory DSA 2184-1 (isc-dhcp)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"dhcp3-client", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-common", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-client-dbg", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-client-udeb", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-common", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-dev", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-relay", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-relay-dbg", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-server-dbg", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-server-ldap", ver:"4.1.1-P1-15+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-client", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-common", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dhcp3-server", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-client-dbg", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-client-udeb", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-common", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-dev", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-relay", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-relay-dbg", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-server-dbg", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"isc-dhcp-server-ldap", ver:"4.1.1-P1-16", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
