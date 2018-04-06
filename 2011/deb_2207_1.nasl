# OpenVAS Vulnerability Test
# $Id: deb_2207_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2207-1 (tomcat5.5)
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
tag_insight = "Various vulnerabilities have been discovered in the Tomcat Servlet and
JSP engine, resulting in denial of service, cross-site scripting,
information disclosure and WAR file traversal. Further details on the
individual security issues can be found at
http://tomcat.apache.org/security-5.html.

For the oldstable distribution (lenny), this problem has been fixed in
version 5.5.26-5lenny2.

The stable distribution (squeeze) no longer contains tomcat5.5. tomcat6
is already fixed.

The unstable distribution (sid) no longer contains tomcat5.5. tomcat6
is already fixed.

We recommend that you upgrade your tomcat5.5 packages.";
tag_summary = "The remote host is missing an update to tomcat5.5
announced via advisory DSA 2207-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202207-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69417");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
 script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783", "CVE-2009-2693", "CVE-2009-2902", "CVE-2010-1157", "CVE-2010-2227");
 script_name("Debian Security Advisory DSA 2207-1 (tomcat5.5)");



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
if ((res = isdpkgvuln(pkg:"libtomcat5.5-java", ver:"5.5.26-5lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat5.5", ver:"5.5.26-5lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat5.5-admin", ver:"5.5.26-5lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat5.5-webapps", ver:"5.5.26-5lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
