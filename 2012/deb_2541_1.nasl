# OpenVAS Vulnerability Test
# $Id: deb_2541_1.nasl 5940 2017-04-12 09:02:05Z teissa $
# Description: Auto-generated from advisory DSA 2541-1 (beaker)
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
tag_insight = "It was discovered that Beaker, a cache and session library for Python,
when using the python-crypto backend, is vulnerable to information
disclosure due to a cryptographic weakness related to the use of the
AES cipher in ECB mode.

Systems that have the python-pycryptopp package should not be
vulnerable, as this backend is preferred over python-crypto.

After applying this update, existing sessions will be invalidated.

For the stable distribution (squeeze), this problem has been fixed in
version 1.5.4-4+squeeze1.

For the testing distribution (wheezy), and the unstable distribution
(sid), this problem has been fixed in version 1.6.3-1.1.

We recommend that you upgrade your beaker packages.";
tag_summary = "The remote host is missing an update to beaker
announced via advisory DSA 2541-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202541-1";

if(description)
{
 script_id(72170);
 script_cve_id("CVE-2012-3458");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_version("$Revision: 5940 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-12 11:02:05 +0200 (Wed, 12 Apr 2017) $");
 script_tag(name:"creation_date", value:"2012-09-15 04:23:55 -0400 (Sat, 15 Sep 2012)");
 script_name("Debian Security Advisory DSA 2541-1 (beaker)");



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
if((res = isdpkgvuln(pkg:"python-beaker", ver:"1.5.4-4+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"python3-beaker", ver:"1.5.4-4+squeeze1", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"python-beaker", ver:"1.6.3-1.1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"python3-beaker", ver:"1.6.3-1.1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
