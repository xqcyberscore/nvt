# OpenVAS Vulnerability Test
# $Id: deb_2307_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2307-1 (chromium-browser)
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
tag_insight = "Several vulnerabilities were discovered in the Chromium browser.
The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2011-2818

Use-after-free vulnerability in Google Chrome allows remote attackers to
cause a denial of service or possibly have unspecified other impact via
vectors related to display box rendering.


CVE-2011-2800

Google Chrome before allows remote attackers to obtain potentially sensitive
information about client-side redirect targets via a crafted web site.


CVE-2011-2359

Google Chrome does not properly track line boxes during rendering, which
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via unknown vectors that lead to a stale pointer.


Several unauthorised SSL certificates have been found in the wild issued
for the DigiNotar Certificate Authority, obtained through a security
compromise with said company.
This update blacklists SSL certificates issued by DigiNotar-controlled
intermediate CAs used by the Dutch PKIoverheid program.


For the stable distribution (squeeze), this problem has been fixed in
version 6.0.472.63~r59945-5+squeeze6.

For the testing distribution (wheezy), this problem has been fixed in
version 13.0.782.220~r99552-1.

For the unstable distribution (sid), this problem has been fixed in
version 13.0.782.220~r99552-1.

We recommend that you upgrade your chromium-browser packages.";
tag_summary = "The remote host is missing an update to chromium-browser
announced via advisory DSA 2307-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202307-1";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70240");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-2359", "CVE-2011-2800", "CVE-2011-2818");
 script_name("Debian Security Advisory DSA 2307-1 (chromium-browser)");



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
if ((res = isdpkgvuln(pkg:"chromium-browser", ver:"6.0.472.63~r59945-5+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"6.0.472.63~r59945-5+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"6.0.472.63~r59945-5+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"6.0.472.63~r59945-5+squeeze6", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium", ver:"13.0.782.220~r99552-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser", ver:"13.0.782.220~r99552-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-dbg", ver:"13.0.782.220~r99552-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-inspector", ver:"13.0.782.220~r99552-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-browser-l10n", ver:"13.0.782.220~r99552-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-dbg", ver:"13.0.782.220~r99552-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-inspector", ver:"13.0.782.220~r99552-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"chromium-l10n", ver:"13.0.782.220~r99552-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
