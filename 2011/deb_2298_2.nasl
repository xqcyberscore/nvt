# OpenVAS Vulnerability Test
# $Id: deb_2298_2.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2298-2 (apache2)
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
tag_insight = "The apache2 Upgrade from DSA-2298-1 has caused a regression that
prevented some video players from seeking in video files served by
Apache HTTPD. This update fixes this bug.


The text of the original advisory is reproduced for reference:

Two issues have been found in the Apache HTTPD web server:

CVE-2011-3192

A vulnerability has been found in the way the multiple overlapping
ranges are handled by the Apache HTTPD server. This vulnerability
allows an attacker to cause Apache HTTPD to use an excessive amount of
memory, causing a denial of service.

CVE-2010-1452

A vulnerability has been found in mod_dav that allows an attacker to
cause a daemon crash, causing a denial of service. This issue only
affects the Debian 5.0 oldstable/lenny distribution.


The regression has been fixed in the following packages:

For the oldstable distribution (lenny), this problem has been fixed
in version 2.2.9-10+lenny11.

For the stable distribution (squeeze), this problem has been fixed in
version 2.2.16-6+squeeze3.

For the testing distribution (wheezy), this problem will be fixed in
version 2.2.20-1.

For the unstable distribution (sid), this problem has been fixed in
version 2.2.20-1.

We recommend that you upgrade your apache2 packages.";
tag_summary = "The remote host is missing an update to apache2
announced via advisory DSA 2298-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202298-2";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70235");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2010-1452", "CVE-2011-3192");
 script_name("Debian Security Advisory DSA 2298-2 (apache2)");



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
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-src", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.9-10+lenny11", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.16-6+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-dbg", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-event", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-itk", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2.2-bin", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2.2-common", ver:"2.2.20-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
