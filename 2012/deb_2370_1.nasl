# OpenVAS Vulnerability Test
# $Id: deb_2370_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2370-1 (unbound)
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
tag_insight = "It was discovered that Unbound, a recursive DNS resolver, would crash
when processing certain malformed DNS responses from authoritative DNS
servers, leading to denial of service.

CVE-2011-4528
Unbound attempts to free unallocated memory during processing
of duplicate CNAME records in a signed zone.

CVE-2011-4869
Unbound does not properly process malformed responses which
lack expected NSEC3 records.

For the oldstable distribution (lenny), these problems have been fixed in
version 1.4.6-1~lenny2.

For the stable distribution (squeeze), these problems have been fixed in
version 1.4.6-1+squeeze2.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 1.4.14-1.

We recommend that you upgrade your unbound packages.";
tag_summary = "The remote host is missing an update to unbound
announced via advisory DSA 2370-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202370-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70689");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2011-4528", "CVE-2011-4869");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-02-11 03:15:52 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2370-1 (unbound)");


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
if((res = isdpkgvuln(pkg:"libunbound-dev", ver:"1.4.6-1~lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libunbound2", ver:"1.4.6-1~lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"unbound", ver:"1.4.6-1~lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"unbound-host", ver:"1.4.6-1~lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libunbound-dev", ver:"1.4.6-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libunbound2", ver:"1.4.6-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"unbound", ver:"1.4.6-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"unbound-host", ver:"1.4.6-1+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libunbound-dev", ver:"1.4.14-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libunbound2", ver:"1.4.14-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"python-unbound", ver:"1.4.14-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"unbound", ver:"1.4.14-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"unbound-anchor", ver:"1.4.14-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"unbound-host", ver:"1.4.14-2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
