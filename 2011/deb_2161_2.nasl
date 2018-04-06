# OpenVAS Vulnerability Test
# $Id: deb_2161_2.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2161-2 (openjdk-6)
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
tag_insight = "It was discovered that the floating point parser in OpenJDK, an
implementation of the Java platform, can enter an infinite loop when
processing certain input strings.  Such input strings represent valid
numbers and can be contained in data supplied by an attacker over the
network, leading to a denial-of-service attack.

For the old stable distribution (lenny), this problem has been fixed
in version 6b18-1.8.3-2~lenny1.

Note that this update introduces an OpenJDK package based on the
IcedTea release 1.8.3 into the old stable distribution.  This
addresses several dozen security vulnerabilities, most of which are
only exploitable by malicious mobile code.  A notable exception is
CVE-2009-3555, the TLS renegotiation vulnerability.  This update
implements the protocol extension described in RFC 5746, addressing
this issue.

This update also includes a new version of Hotspot, the Java virtual
machine, which increases the default heap size on machines with
several GB of RAM.  If you run several JVMs on the same machine, you
might have to reduce the heap size by specifying a suitable -Xmx
argument in the invocation of the java command.

We recommend that you upgrade your openjdk-6 packages.";
tag_summary = "The remote host is missing an update to openjdk-6
announced via advisory DSA 2161-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202161-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68998");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_cve_id("CVE-2010-4476", "CVE-2009-3555");
 script_name("Debian Security Advisory DSA 2161-2 (openjdk-6)");



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
if ((res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b18-1.8.3-2~lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b18-1.8.3-2~lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b18-1.8.3-2~lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b18-1.8.3-2~lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b18-1.8.3-2~lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b18-1.8.3-2~lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b18-1.8.3-2~lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b18-1.8.3-2~lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
