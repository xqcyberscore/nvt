# OpenVAS Vulnerability Test
# $Id: deb_2201_1.nasl 5413 2017-02-24 08:22:28Z teissa $
# Description: Auto-generated from advisory DSA 2201-1 (wireshark)
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
tag_insight = "Huzaifa Sidhpurwala, Joernchen, and Xiaopeng Zhang discovered several
vulnerabilities in the Wireshark network traffic analyzer.
Vulnerabilities in the DCT3, LDAP and SMB dissectors and in the code to
parse pcag-ng files could lead to denial of service or the execution of
arbitrary code.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.0.2-3+lenny13.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.11-6+squeeze1

For the unstable distribution (sid), this problem has been fixed in
version 1.4.4-1.

We recommend that you upgrade your wireshark packages.";
tag_summary = "The remote host is missing an update to wireshark
announced via advisory DSA 2201-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202201-1";


if(description)
{
 script_id(69337);
 script_version("$Revision: 5413 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-24 09:22:28 +0100 (Fri, 24 Feb 2017) $");
 script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-0538", "CVE-2011-0713", "CVE-2011-1139", "CVE-2011-1140", "CVE-2011-1141");
 script_name("Debian Security Advisory DSA 2201-1 (wireshark)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"tshark", ver:"1.0.2-3+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark", ver:"1.0.2-3+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-common", ver:"1.0.2-3+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.0.2-3+lenny13", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tshark", ver:"1.2.11-6+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark", ver:"1.2.11-6+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-common", ver:"1.2.11-6+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dbg", ver:"1.2.11-6+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wireshark-dev", ver:"1.2.11-6+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
