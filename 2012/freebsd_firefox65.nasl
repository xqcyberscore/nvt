#
#VID 380e8c56-8e32-11e1-9580-4061862b8c22
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 380e8c56-8e32-11e1-9580-4061862b8c22
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

CVE-2011-1187
Google Chrome before 10.0.648.127 allows remote attackers to bypass
the Same Origin Policy via unspecified vectors, related to an 'error
message leak.'
CVE-2011-3062
Off-by-one error in the OpenType Sanitizer in Google Chrome before
18.0.1025.142 allows remote attackers to cause a denial of service or
possibly have unspecified other impact via a crafted OpenType file.
CVE-2012-0467
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 4.x through 11.0, Firefox ESR 10.x before 10.0.4, Thunderbird
5.0 through 11.0, Thunderbird ESR 10.x before 10.0.4, and SeaMonkey
before 2.9 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via unknown vectors.
CVE-2012-0468
The browser engine in Mozilla Firefox 4.x through 11.0, Thunderbird
5.0 through 11.0, and SeaMonkey before 2.9 allows remote attackers to
cause a denial of service (assertion failure and memory corruption) or
possibly execute arbitrary code via vectors related to jsval.h and the
js::array_shift function.
CVE-2012-0469
Use-after-free vulnerability in the
mozilla::dom::indexedDB::IDBKeyRange::cycleCollection::Trace function
in Mozilla Firefox 4.x through 11.0, Firefox ESR 10.x before 10.0.4,
Thunderbird 5.0 through 11.0, Thunderbird ESR 10.x before 10.0.4, and
SeaMonkey before 2.9 allows remote attackers to execute arbitrary code
via vectors related to crafted IndexedDB data.
CVE-2012-0470
Heap-based buffer overflow in the
nsSVGFEDiffuseLightingElement::LightPixel function in Mozilla Firefox
4.x through 11.0, Firefox ESR 10.x before 10.0.4, Thunderbird 5.0
through 11.0, Thunderbird ESR 10.x before 10.0.4, and SeaMonkey before
2.9 allows remote attackers to cause a denial of service (invalid
gfxImageSurface free operation) or possibly execute arbitrary code by
leveraging the use of 'different number systems.'
CVE-2012-0471
Cross-site scripting (XSS) vulnerability in Mozilla Firefox 4.x
through 11.0, Firefox ESR 10.x before 10.0.4, Thunderbird 5.0 through
11.0, Thunderbird ESR 10.x before 10.0.4, and SeaMonkey before 2.9
allows remote attackers to inject arbitrary web script or HTML via a
multibyte character set.
CVE-2012-0472
The cairo-dwrite implementation in Mozilla Firefox 4.x through 11.0,
Firefox ESR 10.x before 10.0.4, Thunderbird 5.0 through 11.0,
Thunderbird ESR 10.x before 10.0.4, and SeaMonkey before 2.9, when
certain Windows Vista and Windows 7 configurations are used, does not
properly restrict font-rendering attempts, which allows remote
attackers to cause a denial of service (memory corruption) or possibly
execute arbitrary code via unspecified vectors.
CVE-2012-0473
The WebGLBuffer::FindMaxUshortElement function in Mozilla Firefox 4.x
through 11.0, Firefox ESR 10.x before 10.0.4, Thunderbird 5.0 through
11.0, Thunderbird ESR 10.x before 10.0.4, and SeaMonkey before 2.9
calls the FindMaxElementInSubArray function with incorrect template
arguments, which allows remote attackers to obtain sensitive
information from video memory via a crafted WebGL.drawElements call.
CVE-2012-0474
Cross-site scripting (XSS) vulnerability in the docshell
implementation in Mozilla Firefox 4.x through 11.0, Firefox ESR 10.x
before 10.0.4, Thunderbird 5.0 through 11.0, Thunderbird ESR 10.x
before 10.0.4, and SeaMonkey before 2.9 allows remote attackers to
inject arbitrary web script or HTML via vectors related to
short-circuited page loads, aka 'Universal XSS (UXSS).'
CVE-2012-0475
Mozilla Firefox 4.x through 11.0, Thunderbird 5.0 through 11.0, and
SeaMonkey before 2.9 do not properly construct the Origin and
Sec-WebSocket-Origin HTTP headers, which might allow remote attackers
to bypass an IPv6 literal ACL via a cross-site (1) XMLHttpRequest or
(2) WebSocket operation involving a nonstandard port number and an
IPv6 address that contains certain zero fields.
CVE-2012-0477
Multiple cross-site scripting (XSS) vulnerabilities in Mozilla Firefox
4.x through 11.0, Firefox ESR 10.x before 10.0.4, Thunderbird 5.0
through 11.0, Thunderbird ESR 10.x before 10.0.4, and SeaMonkey before
2.9 allow remote attackers to inject arbitrary web script or HTML via
the (1) ISO-2022-KR or (2) ISO-2022-CN character set.
CVE-2012-0478
The texImage2D implementation in the WebGL subsystem in Mozilla
Firefox 4.x through 11.0, Firefox ESR 10.x before 10.0.4, Thunderbird
5.0 through 11.0, Thunderbird ESR 10.x before 10.0.4, and SeaMonkey
before 2.9 does not properly restrict JSVAL_TO_OBJECT casts, which
might allow remote attackers to execute arbitrary code via a crafted
web page.
CVE-2012-0479
Mozilla Firefox 4.x through 11.0, Firefox ESR 10.x before 10.0.4,
Thunderbird 5.0 through 11.0, Thunderbird ESR 10.x before 10.0.4, and
SeaMonkey before 2.9 allow remote attackers to spoof the address bar
via an https URL for invalid (1) RSS or (2) Atom XML content.
CVE-2012-1126
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via crafted property data in a BDF
font.
CVE-2012-1127
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via crafted glyph or bitmap data in a
BDF font.
CVE-2012-1128
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (NULL pointer dereference and memory corruption) or possibly
execute arbitrary code via a crafted TrueType font.
CVE-2012-1129
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via a crafted SFNT string in a Type 42
font.
CVE-2012-1130
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via crafted property data in a PCF
font.
CVE-2012-1131
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, on 64-bit platforms allows remote attackers to
cause a denial of service (invalid heap read operation and memory
corruption) or possibly execute arbitrary code via vectors related to
the cell table of a font.
CVE-2012-1132
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via crafted dictionary data in a Type
1 font.
CVE-2012-1133
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap write operation and memory corruption) or
possibly execute arbitrary code via crafted glyph or bitmap data in a
BDF font.
CVE-2012-1134
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap write operation and memory corruption) or
possibly execute arbitrary code via crafted private-dictionary data in
a Type 1 font.
CVE-2012-1135
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via vectors involving the NPUSHB and
NPUSHW instructions in a TrueType font.
CVE-2012-1136
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap write operation and memory corruption) or
possibly execute arbitrary code via crafted glyph or bitmap data in a
BDF font that lacks an ENCODING field.
CVE-2012-1137
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via a crafted header in a BDF font.
CVE-2012-1138
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via vectors involving the MIRP
instruction in a TrueType font.
CVE-2012-1139
Array index error in FreeType before 2.4.9, as used in Mozilla Firefox
Mobile before 10.0.4 and other products, allows remote attackers to
cause a denial of service (invalid stack read operation and memory
corruption) or possibly execute arbitrary code via crafted glyph data
in a BDF font.
CVE-2012-1140
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via a crafted PostScript font object.
CVE-2012-1141
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap read operation and memory corruption) or
possibly execute arbitrary code via a crafted ASCII string in a BDF
font.
CVE-2012-1142
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap write operation and memory corruption) or
possibly execute arbitrary code via crafted glyph-outline data in a
font.
CVE-2012-1143
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (divide-by-zero error) via a crafted font.
CVE-2012-1144
FreeType before 2.4.9, as used in Mozilla Firefox Mobile before 10.0.4
and other products, allows remote attackers to cause a denial of
service (invalid heap write operation and memory corruption) or
possibly execute arbitrary code via a crafted TrueType font.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/security/announce/2012/mfsa2012-20.html
http://www.mozilla.org/security/announce/2012/mfsa2012-21.html
http://www.mozilla.org/security/announce/2012/mfsa2012-22.html
http://www.mozilla.org/security/announce/2012/mfsa2012-23.html
http://www.mozilla.org/security/announce/2012/mfsa2012-24.html
http://www.mozilla.org/security/announce/2012/mfsa2012-25.html
http://www.mozilla.org/security/announce/2012/mfsa2012-26.html
http://www.mozilla.org/security/announce/2012/mfsa2012-27.html
http://www.mozilla.org/security/announce/2012/mfsa2012-28.html
http://www.mozilla.org/security/announce/2012/mfsa2012-29.html
http://www.mozilla.org/security/announce/2012/mfsa2012-30.html
http://www.mozilla.org/security/announce/2012/mfsa2012-31.html
http://www.mozilla.org/security/announce/2012/mfsa2012-32.html
http://www.mozilla.org/security/announce/2012/mfsa2012-33.html
http://www.vuxml.org/freebsd/380e8c56-8e32-11e1-9580-4061862b8c22.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71269");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-1187", "CVE-2011-3062", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0472", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0475", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479", "CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1128", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143", "CVE-2012-1144");
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
if(!isnull(bver) && revcomp(a:bver, b:"11.0,1")>0 && revcomp(a:bver, b:"12.0,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.4,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.4,1")<0) {
    txt += "Package linux-firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.9")<0) {
    txt += "Package linux-seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.4")<0) {
    txt += "Package linux-thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.9")<0) {
    txt += "Package seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"11.0")>0 && revcomp(a:bver, b:"12.0")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.4")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"10.0.4")<0) {
    txt += "Package libxul version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
