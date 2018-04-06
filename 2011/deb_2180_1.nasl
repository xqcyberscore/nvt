# OpenVAS Vulnerability Test
# $Id: deb_2180_1.nasl 9351 2018-04-06 07:05:43Z cfischer $
# Description: Auto-generated from advisory DSA 2180-1 (iceape)
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
tag_solution = "The oldstable distribution (lenny) is not affected. The iceape package only
provides the XPCOM code.

For the stable distribution (squeeze), this problem has been fixed in
version 2.0.11-3.

For the unstable distribution (sid), this problem has been fixed in
version 2.0.12-1.

We recommend that you upgrade your iceape packages.

https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202180-1";

tag_insight = "Several vulnerabilities have been found in the Iceape internet suite, an
unbranded version of Seamonkey:

CVE-2010-1585

Roberto Suggi Liverani discovered that the sanitising performed by
ParanoidFragmentSink was incomplete.

CVE-2011-0051

Zach Hoffmann discovered that incorrect parsing of recursive eval()
calls could lead to attackers forcing acceptance of a confirmation
dialogue.

CVE-2011-0053

Crashes in the layout engine may lead to the execution of arbitrary
code.

CVE-2011-0054

Christian Holler discovered buffer overflows in the Javascript engine,
which could allow the execution of arbitrary code.

CVE-2010-0056

Christian Holler discovered buffer overflows in the Javascript engine,
which could allow the execution of arbitrary code.

CVE-2011-0055

regenrecht and Igor Bukanov discovered a use-after-free error in the
JSON-Implementation, which could lead to the execution of arbitrary code.

CVE-2011-0057

Daniel Kozlowski discovered that incorrect memory handling the web workers
implementation could lead to the execution of arbitrary code.

CVE-2011-0059

Peleus Uhley discovered a cross-site request forgery risk in the plugin
code.";
tag_summary = "The remote host is missing an update to iceape
announced via advisory DSA 2180-1.";




if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69115");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2010-1585", "CVE-2011-0051", "CVE-2011-0053", "CVE-2011-0054", "CVE-2011-0055", "CVE-2011-0056", "CVE-2011-0057", "CVE-2011-0059", "CVE-2010-0056");
 script_name("Debian Security Advisory DSA 2180-1 (iceape)");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"iceape", ver:"2.0.11-3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-browser", ver:"2.0.11-3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-chatzilla", ver:"2.0.11-3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-dbg", ver:"2.0.11-3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-dev", ver:"2.0.11-3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"iceape-mailnews", ver:"2.0.11-3", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
