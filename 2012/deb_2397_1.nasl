# OpenVAS Vulnerability Test
# $Id: deb_2397_1.nasl 5963 2017-04-18 09:02:14Z teissa $
# Description: Auto-generated from advisory DSA 2397-1 (icu)
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
tag_insight = "It was discovered that a buffer overflow in the Unicode libraray ICU
could lead to the execution of arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in
version 3.8.1-3+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 4.4.1-8.

For the unstable distribution (sid), this problem has been fixed in
version 4.8.1.1-3.

We recommend that you upgrade your icu packages.";
tag_summary = "The remote host is missing an update to icu
announced via advisory DSA 2397-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202397-1";

if(description)
{
 script_id(70714);
 script_cve_id("CVE-2011-4599");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"cvss_base", value:"7.5");
 script_version("$Revision: 5963 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-18 11:02:14 +0200 (Tue, 18 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-02-12 06:35:00 -0500 (Sun, 12 Feb 2012)");
 script_name("Debian Security Advisory DSA 2397-1 (icu)");


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
if((res = isdpkgvuln(pkg:"icu-doc", ver:"3.8.1-3+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"lib32icu-dev", ver:"3.8.1-3+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"lib32icu38", ver:"3.8.1-3+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libicu-dev", ver:"3.8.1-3+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libicu38", ver:"3.8.1-3+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libicu38-dbg", ver:"3.8.1-3+lenny3", rls:"DEB5.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"icu-doc", ver:"4.4.1-8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"lib32icu-dev", ver:"4.4.1-8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"lib32icu44", ver:"4.4.1-8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libicu-dev", ver:"4.4.1-8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libicu44", ver:"4.4.1-8", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libicu44-dbg", ver:"4.4.1-8", rls:"DEB6.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
