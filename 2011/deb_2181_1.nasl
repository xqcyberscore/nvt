# OpenVAS Vulnerability Test
# $Id: deb_2181_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2181-1 (subversion)
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
tag_solution = "For the oldstable distribution (lenny), this problem has been fixed in
version 1.5.1dfsg1-6.

For the stable distribution (squeeze), this problem has been fixed in
version 1.6.12dfsg-5.

For the testing distribution (wheezy) and the unstable distribution
(sid), this problem will be fixed in version 1.6.16dfsg-1.

We recommend that you upgrade your subversion packages.

https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202181-1";

tag_insight = "Philip Martin discovered that HTTP-based Subversion servers crash when
processing lock requests on repositories which support unauthenticated
read access.";
tag_summary = "The remote host is missing an update to subversion
announced via advisory DSA 2181-1.";




if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69116");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-0715");
 script_name("Debian Security Advisory DSA 2181-1 (subversion)");



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
if ((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.5.1dfsg1-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.5.1dfsg1-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.5.1dfsg1-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-java", ver:"1.5.1dfsg1-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.5.1dfsg1-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.5.1dfsg1-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.5.1dfsg1-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn1", ver:"1.5.1dfsg1-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-subversion", ver:"1.5.1dfsg1-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"subversion", ver:"1.5.1dfsg1-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"subversion-tools", ver:"1.5.1dfsg1-6", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.12dfsg-5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.6.12dfsg-5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.6.12dfsg-5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-java", ver:"1.6.12dfsg-5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.6.12dfsg-5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.6.12dfsg-5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.6.12dfsg-5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.12dfsg-5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-subversion", ver:"1.6.12dfsg-5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"subversion", ver:"1.6.12dfsg-5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"subversion-tools", ver:"1.6.12dfsg-5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.6.16dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.6.16dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.6.16dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-java", ver:"1.6.16dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.6.16dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.6.16dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.6.16dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn1", ver:"1.6.16dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-subversion", ver:"1.6.16dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"subversion", ver:"1.6.16dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"subversion-tools", ver:"1.6.16dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
