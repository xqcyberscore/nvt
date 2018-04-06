# OpenVAS Vulnerability Test
# $Id: deb_2290_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2290-1 (samba)
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
tag_insight = "The Samba Web Administration Tool (SWAT) contains several cross-site
request forgery (CSRF) vulnerabilities (CVE-2011-2522) and a
cross-site scripting vulnerability (CVE-2011-2694).

For the oldstable distribution (lenny), these problems have been fixed in
version 2:3.2.5-4lenny15.

For the stable distribution (squeeze), these problems have been fixed
in version 2:3.5.6~dfsg-3squeeze5.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 2:3.5.10~dfsg-1.

We recommend that you upgrade your samba packages.";
tag_summary = "The remote host is missing an update to samba
announced via advisory DSA 2290-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202290-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70226");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-2522", "CVE-2011-2694");
 script_name("Debian Security Advisory DSA 2290-1 (samba)");



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
if ((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwbclient0", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-tools", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbclient", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbfs", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swat", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"winbind", ver:"2:3.2.5-4lenny15", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwbclient0", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-tools", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbclient", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swat", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"winbind", ver:"2:3.5.6~dfsg-3squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libpam-smbpass", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsmbclient-dev", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwbclient-dev", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libwbclient0", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-common-bin", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-dbg", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-doc-pdf", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"samba-tools", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"smbclient", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"swat", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"winbind", ver:"2:3.5.11~dfsg-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
