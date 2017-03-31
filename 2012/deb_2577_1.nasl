# OpenVAS Vulnerability Test
# $Id: deb_2577_1.nasl 2944 2016-03-24 09:32:58Z benallard $
# Description: Auto-generated from advisory DSA 2577-1 (libssh)
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
tag_insight = "Multiple vulnerabilities were discovered in libssh by Florian Weimer and Xi
Wang:

CVE-2012-4559: multiple double free() flaws
CVE-2012-4561: multiple invalid free() flaws
CVE-2012-4562: multiple improper overflow checks

Those could lead to a denial of service by making an ssh client linked to
libssh crash, and maybe even arbitrary code execution.

For the stable distribution (squeeze), these problems have been fixed in
version 0.4.5-3+squeeze1.

For the testing distribution (wheezy), these problems have been fixed in
version 0.5.3-1.

For the unstable distribution (sid), these problems have been fixed in
version 0.5.3-1.

We recommend that you upgrade your libssh packages.";
tag_summary = "The remote host is missing an update to libssh
announced via advisory DSA 2577-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202577-1";

if(description)
{
 script_id(72627);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-4559", "CVE-2012-4561", "CVE-2012-4562");
 script_version("$Revision: 2944 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-24 10:32:58 +0100 (Thu, 24 Mar 2016) $");
 script_tag(name:"creation_date", value:"2012-12-04 11:43:00 -0500 (Tue, 04 Dec 2012)");
 script_name("Debian Security Advisory DSA 2577-1 (libssh)");


 script_summary("Debian Security Advisory DSA 2577-1 (libssh)");

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
if((res = isdpkgvuln(pkg:"libssh-4", ver:"0.4.5-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssh-dbg", ver:"0.4.5-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssh-dev", ver:"0.4.5-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssh-doc", ver:"0.4.5-3+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssh-4", ver:"0.5.3-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssh-dbg", ver:"0.5.3-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssh-dev", ver:"0.5.3-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libssh-doc", ver:"0.5.3-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
