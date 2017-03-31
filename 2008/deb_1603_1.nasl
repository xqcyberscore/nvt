# OpenVAS Vulnerability Test
# $Id: deb_1603_1.nasl 3925 2016-09-01 04:57:14Z teissa $
# Description: Auto-generated from advisory DSA 1603-1 (bind9)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
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
tag_insight = "Dan Kaminsky discovered that properties inherent to the DNS protocol
lead to practical DNS cache poisoning attacks.  Among other things,
successful attacks can lead to misdirected web traffic and email
rerouting.

This update changes Debian's BIND 9 packages to implement the
recommended countermeasure: UDP query source port randomization.  This
change increases the size of the space from which an attacker has to
guess values in a backwards-compatible fashion and makes successful
attacks significantly more difficult.

For more details on the impact of this update and steps to
take to ensure a smooth upgrade, please visit the referenced
security advisory.

For the stable distribution (etch), this problem has been fixed in
version 9.3.4-2etch3.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your bind9 package.";
tag_summary = "The remote host is missing an update to bind9
announced via advisory DSA 1603-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201603-1";


if(description)
{
 script_id(61249);
 script_version("$Revision: 3925 $");
 script_tag(name:"last_modification", value:"$Date: 2016-09-01 06:57:14 +0200 (Thu, 01 Sep 2016) $");
 script_tag(name:"creation_date", value:"2008-07-15 02:29:31 +0200 (Tue, 15 Jul 2008)");
 script_cve_id("CVE-2008-1447");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_name("Debian Security Advisory DSA 1603-1 (bind9)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"bind9-doc", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccc0", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind-dev", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"lwresd", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisccfg1", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libisc11", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libbind9-0", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libdns22", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"dnsutils", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"liblwres9", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"bind9-host", ver:"9.3.4-2etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
