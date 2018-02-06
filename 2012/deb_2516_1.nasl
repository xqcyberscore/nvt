# OpenVAS Vulnerability Test
# $Id: deb_2516_1.nasl 8671 2018-02-05 16:38:48Z teissa $
# Description: Auto-generated from advisory DSA 2516-1 (isc-dhcp)
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
tag_insight = "Two security vulnerabilities affecting ISC dhcpd, a server for automatic
IP address assignment, in Debian have been discovered.

CVE-2012-3571

Markus Hietava of the Codenomicon CROSS project discovered that it is
possible to force the server to enter an infinite loop via messages with
malformed client identifiers.

CVE-2012-3954

Glen Eustace discovered that DHCP servers running in DHCPv6 mode
and possibly DHCPv4 mode suffer of memory leaks while processing messages.
An attacker can use this flaw to exhaust resources and perform denial
of service attacks.


For the stable distribution (squeeze), this problem has been fixed in
version 4.1.1-P1-15+squeeze4.

For the testing (wheezy) and unstable (sid) distributions, this problem
will be fixed soon.


We recommend that you upgrade your isc-dhcp packages.";
tag_summary = "The remote host is missing an update to isc-dhcp
announced via advisory DSA 2516-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202516-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71493");
 script_tag(name:"cvss_base", value:"6.1");
 script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2012-3571", "CVE-2012-3954");
 script_version("$Revision: 8671 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:14:04 -0400 (Fri, 10 Aug 2012)");
 script_name("Debian Security Advisory DSA 2516-1 (isc-dhcp)");



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
if((res = isdpkgvuln(pkg:"dhcp3-client", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-common", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-dev", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-relay", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"dhcp3-server", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"isc-dhcp-client-dbg", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"isc-dhcp-client-udeb", ver:"4.1.1-P1-15+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"isc-dhcp-common", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"isc-dhcp-dev", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"isc-dhcp-relay", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"isc-dhcp-relay-dbg", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"isc-dhcp-server-dbg", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"isc-dhcp-server-ldap", ver:"4.1.1-P1-15+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
