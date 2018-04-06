#
#VID a1050b8b-6db3-11e1-8b37-0011856a6e37
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID a1050b8b-6db3-11e1-8b37-0011856a6e37
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "The following packages are affected:
   firefox
   linux-firefox
   linux-seamonkey
   linux-thunderbird
   seamonkey
   thunderbird
   libxul

CVE-2012-0451
CRLF injection vulnerability in Mozilla Firefox 4.x through 10.0,
Firefox ESR 10.x before 10.0.3, Thunderbird 5.0 through 10.0,
Thunderbird ESR 10.x before 10.0.3, and SeaMonkey before 2.8 allows
remote web servers to bypass intended Content Security Policy (CSP)
restrictions and possibly conduct cross-site scripting (XSS) attacks
via crafted HTTP headers.
CVE-2012-0455
Mozilla Firefox before 3.6.28 and 4.x through 10.0, Firefox ESR 10.x
before 10.0.3, Thunderbird before 3.1.20 and 5.0 through 10.0,
Thunderbird ESR 10.x before 10.0.3, and SeaMonkey before 2.8 do not
properly restrict drag-and-drop operations on javascript: URLs, which
allows user-assisted remote attackers to conduct cross-site scripting
(XSS) attacks via a crafted web page, related to a
'DragAndDropJacking' issue.
CVE-2012-0456
The SVG Filters implementation in Mozilla Firefox before 3.6.28 and
4.x through 10.0, Firefox ESR 10.x before 10.0.3, Thunderbird before
3.1.20 and 5.0 through 10.0, Thunderbird ESR 10.x before 10.0.3, and
SeaMonkey before 2.8 might allow remote attackers to obtain sensitive
information from process memory via vectors that trigger an
out-of-bounds read.
CVE-2012-0457
Use-after-free vulnerability in the
nsSMILTimeValueSpec::ConvertBetweenTimeContainer function in Mozilla
Firefox before 3.6.28 and 4.x through 10.0, Firefox ESR 10.x before
10.0.3, Thunderbird before 3.1.20 and 5.0 through 10.0, Thunderbird
ESR 10.x before 10.0.3, and SeaMonkey before 2.8 might allow remote
attackers to execute arbitrary code via an SVG animation.
CVE-2012-0458
Mozilla Firefox before 3.6.28 and 4.x through 10.0, Firefox ESR 10.x
before 10.0.3, Thunderbird before 3.1.20 and 5.0 through 10.0,
Thunderbird ESR 10.x before 10.0.3, and SeaMonkey before 2.8 do not
properly restrict setting the home page through the dragging of a URL
to the home button, which allows user-assisted remote attackers to
execute arbitrary JavaScript code with chrome privileges via a
javascript: URL that is later interpreted in the about:sessionrestore
context.
CVE-2012-0459
The Cascading Style Sheets (CSS) implementation in Mozilla Firefox 4.x
through 10.0, Firefox ESR 10.x before 10.0.3, Thunderbird 5.0 through
10.0, Thunderbird ESR 10.x before 10.0.3, and SeaMonkey before 2.8
allows remote attackers to cause a denial of service (application
crash) or possibly execute arbitrary code via dynamic modification of
a keyframe followed by access to the cssText of the keyframe.
CVE-2012-0460
Mozilla Firefox 4.x through 10.0, Firefox ESR 10.x before 10.0.3,
Thunderbird 5.0 through 10.0, Thunderbird ESR 10.x before 10.0.3, and
SeaMonkey before 2.8 do not properly restrict write access to the
window.fullScreen object, which allows remote attackers to spoof the
user interface via a crafted web page.
CVE-2012-0461
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 3.6.28 and 4.x through 10.0, Firefox ESR 10.x before
10.0.3, Thunderbird before 3.1.20 and 5.0 through 10.0, Thunderbird
ESR 10.x before 10.0.3, and SeaMonkey before 2.8 allow remote
attackers to cause a denial of service (memory corruption and
application crash) or possibly execute arbitrary code via unknown
vectors.
CVE-2012-0462
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 4.x through 10.0, Firefox ESR 10.x before 10.0.3, Thunderbird
5.0 through 10.0, Thunderbird ESR 10.x before 10.0.3, and SeaMonkey
before 2.8 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via unknown vectors.
CVE-2012-0463
The nsWindow implementation in the browser engine in Mozilla Firefox
before 3.6.28 and 4.x through 10.0, Firefox ESR 10.x before 10.0.3,
Thunderbird before 3.1.20 and 5.0 through 10.0, Thunderbird ESR 10.x
before 10.0.3, and SeaMonkey before 2.8 does not check the validity of
an instance after event dispatching, which allows remote attackers to
cause a denial of service (memory corruption and application crash) or
possibly execute arbitrary code via unknown vectors, as demonstrated
by Mobile Firefox on Android.
CVE-2012-0464
Use-after-free vulnerability in the browser engine in Mozilla Firefox
before 3.6.28 and 4.x through 10.0, Firefox ESR 10.x before 10.0.3,
Thunderbird before 3.1.20 and 5.0 through 10.0, Thunderbird ESR 10.x
before 10.0.3, and SeaMonkey before 2.8 allows remote attackers to
execute arbitrary code via vectors involving an empty argument to the
array.join function in conjunction with the triggering of garbage
collection.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/security/announce/2012/mfsa2012-13.html
http://www.mozilla.org/security/announce/2012/mfsa2012-14.html
http://www.mozilla.org/security/announce/2012/mfsa2012-15.html
http://www.mozilla.org/security/announce/2012/mfsa2012-16.html
http://www.mozilla.org/security/announce/2012/mfsa2012-17.html
http://www.mozilla.org/security/announce/2012/mfsa2012-18.html
http://www.mozilla.org/security/announce/2012/mfsa2012-19.html
http://www.vuxml.org/freebsd/a1050b8b-6db3-11e1-8b37-0011856a6e37.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71298");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-0451", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461", "CVE-2012-0462", "CVE-2012-0463", "CVE-2012-0464");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)");
 script_name("FreeBSD Ports: firefox");


 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name:"qod_type", value:"package");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");
vuln = 0;
txt = "";
bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"4.0,1")>0 && revcomp(a:bver, b:"10.0.3,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.6.*,1")>=0 && revcomp(a:bver, b:"3.6.28")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.3,1")<0) {
    txt += "Package linux-firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.8")<0) {
    txt += "Package linux-seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.3")<0) {
    txt += "Package linux-thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.8")<0) {
    txt += "Package seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>0 && revcomp(a:bver, b:"10.0.3")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.1")>0 && revcomp(a:bver, b:"3.1.20")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"1.9.2.28")<0) {
    txt += "Package libxul version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
