# OpenVAS Vulnerability Test
# $Id: deb_2429_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2429-1 (mysql-5.1)
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
tag_insight = "Several security vulnerabilities were discovered in MySQL, a database
management system.  The vulnerabilities are addressed by upgrading
MySQL to a new upstream version, 5.1.61, which includes additional
changes, such as performance improvements and corrections for data
loss defects.  These changes are described in the MySQL release notes
at: http://dev.mysql.com/doc/refman/5.1/en/news-5-1-x.html

For the stable distribution (squeeze), these problems have been fixed
in version 5.1.61-0+squeeze1.

For the unstable distribution (sid), these problems have been fixed in
version 5.1.61-2.

We recommend that you upgrade your mysql-5.1 packages.";
tag_summary = "The remote host is missing an update to mysql-5.1
announced via advisory DSA 2429-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202429-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71233");
 script_tag(name:"cvss_base", value:"5.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
 script_cve_id("CVE-2011-2262", "CVE-2012-0075", "CVE-2012-0087", "CVE-2012-0101", "CVE-2012-0102", "CVE-2012-0112", "CVE-2012-0113", "CVE-2012-0114", "CVE-2012-0115", "CVE-2012-0116", "CVE-2012-0118", "CVE-2012-0119", "CVE-2012-0120", "CVE-2012-0484", "CVE-2012-0485", "CVE-2012-0490", "CVE-2012-0492");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-04-30 07:54:07 -0400 (Mon, 30 Apr 2012)");
 script_name("Debian Security Advisory DSA 2429-1 (mysql-5.1)");



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
if((res = isdpkgvuln(pkg:"libmysqlclient-dev", ver:"5.1.61-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libmysqlclient16", ver:"5.1.61-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libmysqld-dev", ver:"5.1.61-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libmysqld-pic", ver:"5.1.61-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"mysql-client", ver:"5.1.61-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"mysql-client-5.1", ver:"5.1.61-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"mysql-common", ver:"5.1.61-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"mysql-server", ver:"5.1.61-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"mysql-server-5.1", ver:"5.1.61-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"mysql-server-core-5.1", ver:"5.1.61-0+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
