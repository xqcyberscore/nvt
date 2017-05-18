# OpenVAS Vulnerability Test
# $Id: deb_2555_1.nasl 5958 2017-04-17 09:02:19Z teissa $
# Description: Auto-generated from advisory DSA 2555-1 (libxslt)
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
tag_insight = "Nicholas Gregoire and Cris Neckar discovered several memory handling
bugs in libxslt, which could lead to denial of service or the execution
of arbitrary code if a malformed document is processed.

For the stable distribution (squeeze), these problems have been fixed in
version 1.1.26-6+squeeze2.

For the unstable distribution (sid), these problems have been fixed in
version 1.1.26-14.

We recommend that you upgrade your libxslt packages.";
tag_summary = "The remote host is missing an update to libxslt
announced via advisory DSA 2555-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202555-1";

if(description)
{
 script_id(72472);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-2870", "CVE-2012-2871", "CVE-2012-2893");
 script_version("$Revision: 5958 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-17 11:02:19 +0200 (Mon, 17 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-10-13 02:34:19 -0400 (Sat, 13 Oct 2012)");
 script_name("Debian Security Advisory DSA 2555-1 (libxslt)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
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
if((res = isdpkgvuln(pkg:"libxslt1-dbg", ver:"1.1.26-6+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libxslt1-dev", ver:"1.1.26-6+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libxslt1.1", ver:"1.1.26-6+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"python-libxslt1", ver:"1.1.26-6+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"python-libxslt1-dbg", ver:"1.1.26-6+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"xsltproc", ver:"1.1.26-6+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
