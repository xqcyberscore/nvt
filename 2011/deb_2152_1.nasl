# OpenVAS Vulnerability Test
# $Id: deb_2152_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2152-1 (hplip)
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
tag_insight = "Sebastian Krahmer discovered a buffer overflow in the SNMP discovery code
of the HP Linux Printing and Imaging System, which could result in the
execution of arbitrary code.

For the stable distribution (lenny), this problem has been fixed in
version 2.8.6.b-4+lenny1.

For the testing distribution (squeeze), this problem has been fixed in
version 3.10.6-2.

For the unstable distribution (sid), this problem has been fixed in
version 3.10.6-2.

For the experimental distribution, this problem has been fixed in
version 3.11.1-1.

We recommend that you upgrade your hplip packages.";
tag_summary = "The remote host is missing an update to hplip
announced via advisory DSA 2152-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202152-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68990");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-4267");
 script_name("Debian Security Advisory DSA 2152-1 (hplip)");



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
if ((res = isdpkgvuln(pkg:"hpijs", ver:"2.8.6.b-4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hpijs-ppds", ver:"2.8.6.b-4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip", ver:"2.8.6.b-4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-data", ver:"2.8.6.b-4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-dbg", ver:"2.8.6.b-4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-doc", ver:"2.8.6.b-4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-gui", ver:"2.8.6.b-4+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hpijs", ver:"3.10.6-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hpijs-ppds", ver:"3.10.6-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip", ver:"3.10.6-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-cups", ver:"3.10.6-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-data", ver:"3.10.6-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-dbg", ver:"3.10.6-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-doc", ver:"3.10.6-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"hplip-gui", ver:"3.10.6-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libhpmud-dev", ver:"3.10.6-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libhpmud0", ver:"3.10.6-2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsane-hpaio", ver:"3.10.6-2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
