# OpenVAS Vulnerability Test
# $Id: deb_2491_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2491-1 (postgresql-8.4)
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
tag_insight = "Two vulnerabilities were discovered in PostgreSQL, an SQL database
server:

CVE-2012-2143
The crypt(text, text) function in the pgcrypto contrib module
did not handle certain passwords correctly, ignoring
characters after the first character which does not fall into
the ASCII range.

CVE-2012-2655
SECURITY DEFINER and SET attributes for a call handler of a
procedural language could crash the database server.

In addition, this update contains reliability and stability fixes from
the 8.4.12 upstream release.

For the stable distribution (squeeze), this problem has been fixed in
version 8.4.12-0squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 8.4.12-1.

We recommend that you upgrade your postgresql-8.4 packages.";
tag_summary = "The remote host is missing an update to postgresql-8.4
announced via advisory DSA 2491-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202491-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71469");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_cve_id("CVE-2012-2143", "CVE-2012-2655");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:03:13 -0400 (Fri, 10 Aug 2012)");
 script_name("Debian Security Advisory DSA 2491-1 (postgresql-8.4)");



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
if((res = isdpkgvuln(pkg:"libecpg-compat3", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libecpg-dev", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libecpg6", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libpgtypes3", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libpq-dev", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libpq5", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-8.4", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-client", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-client-8.4", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-contrib", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-contrib-8.4", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-doc", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-doc-8.4", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-plperl-8.4", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-plpython-8.4", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-pltcl-8.4", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"postgresql-server-dev-8.4", ver:"8.4.12-0squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
