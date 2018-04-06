# OpenVAS Vulnerability Test
# $Id: deb_2569_1.nasl 9352 2018-04-06 07:13:02Z cfischer $
# Description: Auto-generated from advisory DSA 2569-1 (icedove)
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
tag_insight = "Multiple vulnerabilities have been discovered in Icedove, Debian's
version of the Mozilla Thunderbird mail client.  The Common
Vulnerabilities and Exposures project identifies the following
problems:

CVE-2012-3982
Multiple unspecified vulnerabilities in the browser engine
allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute
arbitrary code via unknown vectors.

CVE-2012-3986
Icedove does not properly restrict calls to DOMWindowUtils
methods, which allows remote attackers to bypass intended
access restrictions via crafted JavaScript code.

CVE-2012-3990
A Use-after-free vulnerability in the IME State Manager
implementation allows remote attackers to execute arbitrary
code via unspecified vectors, related to the
nsIContent::GetNameSpaceID function.

CVE-2012-3991
Icedove does not properly restrict JSAPI access to the
GetProperty function, which allows remote attackers to bypass
the Same Origin Policy and possibly have unspecified other
impact via a crafted web site.

CVE-2012-4179
A use-after-free vulnerability in the
nsHTMLCSSUtils::CreateCSSPropertyTxn function allows remote
attackers to execute arbitrary code or cause a denial of
service (heap memory corruption) via unspecified vectors.

CVE-2012-4180
A heap-based buffer overflow in the
nsHTMLEditor::IsPrevCharInNodeWhitespace function allows
remote attackers to execute arbitrary code via unspecified
vectors.

CVE-2012-4182
A use-after-free vulnerability in the
nsTextEditRules::WillInsert function allows remote attackers
to execute arbitrary code or cause a denial of service (heap
memory corruption) via unspecified vectors.

CVE-2012-4186
A heap-based buffer overflow in the
nsWav-eReader::DecodeAudioData function allows remote attackers
to execute arbitrary code via unspecified vectors.

CVE-2012-4188
A heap-based buffer overflow in the Convolve3x3 function
allows remote attackers to execute arbitrary code via
unspecified vectors.

For the stable distribution (squeeze), these problems have been fixed
in version 3.0.11-1+squeeze14.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 10.0.9-1.

We recommend that you upgrade your icedove packages.";
tag_summary = "The remote host is missing an update to icedove
announced via advisory DSA 2569-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202569-1";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72564");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-3982", "CVE-2012-3986", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4182", "CVE-2012-4186", "CVE-2012-4188");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-11-16 03:09:50 -0500 (Fri, 16 Nov 2012)");
 script_name("Debian Security Advisory DSA 2569-1 (icedove)");



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
if((res = isdpkgvuln(pkg:"icedove", ver:"3.0.11-1+squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dbg", ver:"3.0.11-1+squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dev", ver:"3.0.11-1+squeeze14", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"calendar-google-provider", ver:"10.0.10-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"calendar-timezones", ver:"10.0.10-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"icedove", ver:"10.0.10-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dbg", ver:"10.0.10-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"icedove-dev", ver:"10.0.10-1", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"iceowl-extension", ver:"10.0.10-1", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
