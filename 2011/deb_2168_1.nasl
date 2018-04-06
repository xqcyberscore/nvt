# OpenVAS Vulnerability Test
# $Id: deb_2168_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2168-1 (openafs)
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
tag_insight = "Two vulnerabilities were discovered the distributed filesystem AFS:

CVE-2011-0430

Andrew Deason discovered that a double free in the Rx server
process could lead to denial of service or the execution of
arbitrary code.

CVE-2011-0431

It was discovered that insufficient error handling in the
kernel module could lead to denial of service.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.4.7.dfsg1-6+lenny4. Due to a technical problem with the
buildd infrastructure the update is not yet available, but will be
installed into the archive soon.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.12.1+dfsg-4.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.14+dfsg-1.

We recommend that you upgrade your openafs packages. Note that in order";
tag_summary = "The remote host is missing an update to openafs
announced via advisory DSA 2168-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202168-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69001");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-0430", "CVE-2011-0431");
 script_name("Debian Security Advisory DSA 2168-1 (openafs)");



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
if ((res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.4.7.dfsg1-6+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-openafs-kaserver", ver:"1.4.7.dfsg1-6+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-client", ver:"1.4.7.dfsg1-6+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-dbg", ver:"1.4.7.dfsg1-6+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.4.7.dfsg1-6+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-doc", ver:"1.4.7.dfsg1-6+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.4.7.dfsg1-6+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.4.7.dfsg1-6+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-krb5", ver:"1.4.7.dfsg1-6+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.4.7.dfsg1-6+lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libopenafs-dev", ver:"1.4.12.1+dfsg-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-openafs-kaserver", ver:"1.4.12.1+dfsg-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-client", ver:"1.4.12.1+dfsg-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-dbg", ver:"1.4.12.1+dfsg-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-dbserver", ver:"1.4.12.1+dfsg-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-doc", ver:"1.4.12.1+dfsg-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-fileserver", ver:"1.4.12.1+dfsg-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-kpasswd", ver:"1.4.12.1+dfsg-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-krb5", ver:"1.4.12.1+dfsg-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-modules-dkms", ver:"1.4.12.1+dfsg-4", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"openafs-modules-source", ver:"1.4.12.1+dfsg-4", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
