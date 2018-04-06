#
#VID 6e5a9afd-12d3-11e2-b47d-c8600054b392
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 6e5a9afd-12d3-11e2-b47d-c8600054b392
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

CVE-2012-3982
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 16.0, Firefox ESR 10.x before 10.0.8, Thunderbird
before 16.0, Thunderbird ESR 10.x before 10.0.8, and SeaMonkey before
2.13 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via unknown vectors.
CVE-2012-3983
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 16.0, Thunderbird before 16.0, and SeaMonkey before
2.13 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via unknown vectors.
CVE-2012-3984
Mozilla Firefox before 16.0, Thunderbird before 16.0, and SeaMonkey
before 2.13 do not properly handle navigation away from a web page
that has a SELECT element's menu active, which allows remote attackers
to spoof page content via vectors involving absolute positioning and
scrolling.
CVE-2012-3985
Mozilla Firefox before 16.0, Thunderbird before 16.0, and SeaMonkey
before 2.13 do not properly implement the HTML5 Same Origin Policy,
which allows remote attackers to conduct cross-site scripting (XSS)
attacks by leveraging initial-origin access after document.domain has
been set.
CVE-2012-3986
Mozilla Firefox before 16.0, Firefox ESR 10.x before 10.0.8,
Thunderbird before 16.0, Thunderbird ESR 10.x before 10.0.8, and
SeaMonkey before 2.13 do not properly restrict calls to DOMWindowUtils
(aka nsDOMWindowUtils) methods, which allows remote attackers to
bypass intended access restrictions via crafted JavaScript code.
CVE-2012-3987
Mozilla Firefox before 16.0 on Android assigns chrome privileges to
Reader Mode pages, which allows user-assisted remote attackers to
bypass intended access restrictions via a crafted web site.
CVE-2012-3988
Use-after-free vulnerability in Mozilla Firefox before 16.0, Firefox
ESR 10.x before 10.0.8, Thunderbird before 16.0, Thunderbird ESR 10.x
before 10.0.8, and SeaMonkey before 2.13 might allow user-assisted
remote attackers to execute arbitrary code via vectors involving use
of mozRequestFullScreen to enter full-screen mode, and use of the
history.back method for backwards history navigation.
CVE-2012-3989
Mozilla Firefox before 16.0, Thunderbird before 16.0, and SeaMonkey
before 2.13 do not properly perform a cast of an unspecified variable
during use of the instanceof operator on a JavaScript object, which
allows remote attackers to execute arbitrary code or cause a denial of
service (assertion failure) via a crafted web site.
CVE-2012-3990
Use-after-free vulnerability in the IME State Manager implementation
in Mozilla Firefox before 16.0, Firefox ESR 10.x before 10.0.8,
Thunderbird before 16.0, Thunderbird ESR 10.x before 10.0.8, and
SeaMonkey before 2.13 allows remote attackers to execute arbitrary
code via unspecified vectors, related to the
nsIContent::GetNameSpaceID function.
CVE-2012-3991
Mozilla Firefox before 16.0, Firefox ESR 10.x before 10.0.8,
Thunderbird before 16.0, Thunderbird ESR 10.x before 10.0.8, and
SeaMonkey before 2.13 do not properly restrict JSAPI access to the
GetProperty function, which allows remote attackers to bypass the Same
Origin Policy and possibly have unspecified other impact via a crafted
web site.
CVE-2012-3992
Mozilla Firefox before 16.0, Firefox ESR 10.x before 10.0.8,
Thunderbird before 16.0, Thunderbird ESR 10.x before 10.0.8, and
SeaMonkey before 2.13 do not properly manage history data, which
allows remote attackers to conduct cross-site scripting (XSS) attacks
or obtain sensitive POST content via vectors involving a location.hash
write operation and history navigation that triggers the loading of a
URL into the history object.
CVE-2012-3993
The Chrome Object Wrapper (COW) implementation in Mozilla Firefox
before 16.0, Firefox ESR 10.x before 10.0.8, Thunderbird before 16.0,
Thunderbird ESR 10.x before 10.0.8, and SeaMonkey before 2.13 does not
properly interact with failures of InstallTrigger methods, which
allows remote attackers to execute arbitrary JavaScript code with
chrome privileges via a crafted web site, related to an 'XrayWrapper
pollution' issue.
CVE-2012-3994
Mozilla Firefox before 16.0, Firefox ESR 10.x before 10.0.8,
Thunderbird before 16.0, Thunderbird ESR 10.x before 10.0.8, and
SeaMonkey before 2.13 allow remote attackers to conduct cross-site
scripting (XSS) attacks via a binary plugin that uses
Object.defineProperty to shadow the top object, and leverages the
relationship between top.location and the location property.
CVE-2012-3995
The IsCSSWordSpacingSpace function in Mozilla Firefox before 16.0,
Firefox ESR 10.x before 10.0.8, Thunderbird before 16.0, Thunderbird
ESR 10.x before 10.0.8, and SeaMonkey before 2.13 allows remote
attackers to execute arbitrary code or cause a denial of service
(out-of-bounds read) via unspecified vectors.
CVE-2012-4179
Use-after-free vulnerability in the
nsHTMLCSSUtils::CreateCSSPropertyTxn function in Mozilla Firefox
before 16.0, Firefox ESR 10.x before 10.0.8, Thunderbird before 16.0,
Thunderbird ESR 10.x before 10.0.8, and SeaMonkey before 2.13 allows
remote attackers to execute arbitrary code or cause a denial of
service (heap memory corruption) via unspecified vectors.
CVE-2012-4180
Heap-based buffer overflow in the
nsHTMLEditor::IsPrevCharInNodeWhitespace function in Mozilla Firefox
before 16.0, Firefox ESR 10.x before 10.0.8, Thunderbird before 16.0,
Thunderbird ESR 10.x before 10.0.8, and SeaMonkey before 2.13 allows
remote attackers to execute arbitrary code via unspecified vectors.
CVE-2012-4181
Use-after-free vulnerability in the
nsSMILAnimationController::DoSample function in Mozilla Firefox before
16.0, Firefox ESR 10.x before 10.0.8, Thunderbird before 16.0,
Thunderbird ESR 10.x before 10.0.8, and SeaMonkey before 2.13 allows
remote attackers to execute arbitrary code or cause a denial of
service (heap memory corruption) via unspecified vectors.
CVE-2012-4182
Use-after-free vulnerability in the nsTextEditRules::WillInsert
function in Mozilla Firefox before 16.0, Firefox ESR 10.x before
10.0.8, Thunderbird before 16.0, Thunderbird ESR 10.x before 10.0.8,
and SeaMonkey before 2.13 allows remote attackers to execute arbitrary
code or cause a denial of service (heap memory corruption) via
unspecified vectors.
CVE-2012-4183
Use-after-free vulnerability in the DOMSVGTests::GetRequiredFeatures
function in Mozilla Firefox before 16.0, Firefox ESR 10.x before
10.0.8, Thunderbird before 16.0, Thunderbird ESR 10.x before 10.0.8,
and SeaMonkey before 2.13 allows remote attackers to execute arbitrary
code or cause a denial of service (heap memory corruption) via
unspecified vectors.
CVE-2012-4184
The Chrome Object Wrapper (COW) implementation in Mozilla Firefox
before 16.0, Firefox ESR 10.x before 10.0.8, Thunderbird before 16.0,
Thunderbird ESR 10.x before 10.0.8, and SeaMonkey before 2.13 does not
prevent access to properties of a prototype for a standard class,
which allows remote attackers to execute arbitrary JavaScript code
with chrome privileges via a crafted web site.
CVE-2012-4186
Heap-based buffer overflow in the nsWaveReader::DecodeAudioData
function in Mozilla Firefox before 16.0, Firefox ESR 10.x before
10.0.8, Thunderbird before 16.0, Thunderbird ESR 10.x before 10.0.8,
and SeaMonkey before 2.13 allows remote attackers to execute arbitrary
code via unspecified vectors.
CVE-2012-4187
Mozilla Firefox before 16.0, Firefox ESR 10.x before 10.0.8,
Thunderbird before 16.0, Thunderbird ESR 10.x before 10.0.8, and
SeaMonkey before 2.13 do not properly manage a certain insPos
variable, which allows remote attackers to execute arbitrary code or
cause a denial of service (heap memory corruption and assertion
failure) via unspecified vectors.
CVE-2012-4188
Heap-based buffer overflow in the Convolve3x3 function in Mozilla
Firefox before 16.0, Firefox ESR 10.x before 10.0.8, Thunderbird
before 16.0, Thunderbird ESR 10.x before 10.0.8, and SeaMonkey before
2.13 allows remote attackers to execute arbitrary code via unspecified
vectors.
CVE-2012-4190
The FT2FontEntry::CreateFontEntry function in FreeType, as used in the
Android build of Mozilla Firefox before 16.0.1 on CyanogenMod 10,
allows remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via unspecified vectors.
CVE-2012-4191
The mozilla::net::FailDelayManager::Lookup function in the WebSockets
implementation in Mozilla Firefox before 16.0.1, Thunderbird before
16.0.1, and SeaMonkey before 2.13.1 allows remote attackers to cause a
denial of service (memory corruption and application crash) or
possibly execute arbitrary code via unspecified vectors.
CVE-2012-4192
Mozilla Firefox 16.0, Thunderbird 16.0, and SeaMonkey 2.13 allow
remote attackers to bypass the Same Origin Policy and read the
properties of a Location object via a crafted web site, a related
issue to CVE-2012-4193.
CVE-2012-4193
Mozilla Firefox before 16.0.1, Firefox ESR 10.x before 10.0.9,
Thunderbird before 16.0.1, Thunderbird ESR 10.x before 10.0.9, and
SeaMonkey before 2.13.1 omit a security check in the defaultValue
function during the unwrapping of security wrappers, which allows
remote attackers to bypass the Same Origin Policy and read the
properties of a Location object, or execute arbitrary JavaScript code,
via a crafted web site.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/security/known-vulnerabilities/
http://www.mozilla.org/security/announce/2012/mfsa2012-74.html
http://www.mozilla.org/security/announce/2012/mfsa2012-75.html
http://www.mozilla.org/security/announce/2012/mfsa2012-76.html
http://www.mozilla.org/security/announce/2012/mfsa2012-77.html
http://www.mozilla.org/security/announce/2012/mfsa2012-78.html
http://www.mozilla.org/security/announce/2012/mfsa2012-79.html
http://www.mozilla.org/security/announce/2012/mfsa2012-80.html
http://www.mozilla.org/security/announce/2012/mfsa2012-81.html
http://www.mozilla.org/security/announce/2012/mfsa2012-82.html
http://www.mozilla.org/security/announce/2012/mfsa2012-83.html
http://www.mozilla.org/security/announce/2012/mfsa2012-84.html
http://www.mozilla.org/security/announce/2012/mfsa2012-85.html
http://www.mozilla.org/security/announce/2012/mfsa2012-86.html
http://www.mozilla.org/security/announce/2012/mfsa2012-87.html
http://www.mozilla.org/security/announce/2012/mfsa2012-88.html
http://www.mozilla.org/security/announce/2012/mfsa2012-89.html
http://www.vuxml.org/freebsd/6e5a9afd-12d3-11e2-b47d-c8600054b392.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72477");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-3982", "CVE-2012-3983", "CVE-2012-3984", "CVE-2012-3985", "CVE-2012-3986", "CVE-2012-3987", "CVE-2012-3988", "CVE-2012-3989", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188", "CVE-2012-4190", "CVE-2012-4191", "CVE-2012-4192", "CVE-2012-4193");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-10-13 02:35:34 -0400 (Sat, 13 Oct 2012)");
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
if(!isnull(bver) && revcomp(a:bver, b:"11.0,1")>0 && revcomp(a:bver, b:"16.0.1,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.9,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.9,1")<0) {
    txt += "Package linux-firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.13.1")<0) {
    txt += "Package linux-seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.9")<0) {
    txt += "Package linux-thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.13.1")<0) {
    txt += "Package seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"11.0")>0 && revcomp(a:bver, b:"16.0.1")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.9")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"10.0.9")<0) {
    txt += "Package libxul version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99);
}
