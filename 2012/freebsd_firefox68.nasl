#
#VID bfecf7c1-af47-11e1-9580-4061862b8c22
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID bfecf7c1-af47-11e1-9580-4061862b8c22
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

CVE-2011-3101
Google Chrome before 19.0.1084.46 on Linux does not properly mitigate
an unspecified flaw in an NVIDIA driver, which has unknown impact and
attack vectors.  NOTE: see CVE-2012-3105 for the related MFSA 2012-34
issue in Mozilla products.
CVE-2012-0441
The ASN.1 decoder in the QuickDER decoder in Mozilla Network Security
Services (NSS) before 3.13.4, as used in Firefox 4.x through 12.0,
Firefox ESR 10.x before 10.0.5, Thunderbird 5.0 through 12.0,
Thunderbird ESR 10.x before 10.0.5, and SeaMonkey before 2.10, allows
remote attackers to cause a denial of service (application crash) via
a zero-length item, as demonstrated by (1) a zero-length basic
constraint or (2) a zero-length field in an OCSP response.
CVE-2012-1938
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 13.0, Thunderbird before 13.0, and SeaMonkey before
2.10 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via vectors related to (1) methodjit/ImmutableSync.cpp, (2) the
JSObject::makeDenseArraySlow function in js/src/jsarray.cpp, and
unknown other components.
CVE-2012-1939
jsinfer.cpp in Mozilla Firefox ESR 10.x before 10.0.5 and Thunderbird
ESR 10.x before 10.0.5 does not properly determine data types, which
allows remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via crafted JavaScript code.
CVE-2012-1937
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 4.x through 12.0, Firefox ESR 10.x before 10.0.5, Thunderbird
5.0 through 12.0, Thunderbird ESR 10.x before 10.0.5, and SeaMonkey
before 2.10 allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute
arbitrary code via unknown vectors.
CVE-2012-1940
Use-after-free vulnerability in the nsFrameList::FirstChild function
in Mozilla Firefox 4.x through 12.0, Firefox ESR 10.x before 10.0.5,
Thunderbird 5.0 through 12.0, Thunderbird ESR 10.x before 10.0.5, and
SeaMonkey before 2.10 allows remote attackers to execute arbitrary
code or cause a denial of service (heap memory corruption and
application crash) by changing the size of a container of absolutely
positioned elements in a column.
CVE-2012-1941
Heap-based buffer overflow in the
nsHTMLReflowState::CalculateHypotheticalBox function in Mozilla
Firefox 4.x through 12.0, Firefox ESR 10.x before 10.0.5, Thunderbird
5.0 through 12.0, Thunderbird ESR 10.x before 10.0.5, and SeaMonkey
before 2.10 allows remote attackers to execute arbitrary code by
resizing a window displaying absolutely positioned and relatively
positioned elements in nested columns.
CVE-2012-1944
The Content Security Policy (CSP) implementation in Mozilla Firefox
4.x through 12.0, Firefox ESR 10.x before 10.0.5, Thunderbird 5.0
through 12.0, Thunderbird ESR 10.x before 10.0.5, and SeaMonkey before
2.10 does not block inline event handlers, which makes it easier for
remote attackers to conduct cross-site scripting (XSS) attacks via a
crafted HTML document.
CVE-2012-1945
Mozilla Firefox 4.x through 12.0, Firefox ESR 10.x before 10.0.5,
Thunderbird 5.0 through 12.0, Thunderbird ESR 10.x before 10.0.5, and
SeaMonkey before 2.10 allow local users to obtain sensitive
information via an HTML document that loads a shortcut (aka .lnk) file
for display within an IFRAME element, as demonstrated by a network
share implemented by (1) Microsoft Windows or (2) Samba.
CVE-2012-1946
Use-after-free vulnerability in the nsINode::ReplaceOrInsertBefore
function in Mozilla Firefox 4.x through 12.0, Firefox ESR 10.x before
10.0.5, Thunderbird 5.0 through 12.0, Thunderbird ESR 10.x before
10.0.5, and SeaMonkey before 2.10 might allow remote attackers to
execute arbitrary code via document changes involving replacement or
insertion of a node.
CVE-2012-1947
Heap-based buffer overflow in the utf16_to_isolatin1 function in
Mozilla Firefox 4.x through 12.0, Firefox ESR 10.x before 10.0.5,
Thunderbird 5.0 through 12.0, Thunderbird ESR 10.x before 10.0.5, and
SeaMonkey before 2.10 allows remote attackers to execute arbitrary
code via vectors that trigger a character-set conversion failure.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/security/known-vulnerabilities/
http://www.mozilla.org/security/announce/2012/mfsa2012-34.html
http://www.mozilla.org/security/announce/2012/mfsa2012-36.html
http://www.mozilla.org/security/announce/2012/mfsa2012-37.html
http://www.mozilla.org/security/announce/2012/mfsa2012-38.html
http://www.mozilla.org/security/announce/2012/mfsa2012-39.html
http://www.mozilla.org/security/announce/2012/mfsa2012-40.html
http://www.vuxml.org/freebsd/bfecf7c1-af47-11e1-9580-4061862b8c22.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71541");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-3101", "CVE-2012-0441", "CVE-2012-1938", "CVE-2012-1939", "CVE-2012-1937", "CVE-2012-1940", "CVE-2012-1941", "CVE-2012-1944", "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-1947");
 script_version("$Revision: 8649 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
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
if(!isnull(bver) && revcomp(a:bver, b:"11.0,1")>0 && revcomp(a:bver, b:"13.0,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.5,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.5,1")<0) {
    txt += "Package linux-firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.10")<0) {
    txt += "Package linux-seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.5")<0) {
    txt += "Package linux-thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.10")<0) {
    txt += "Package seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"11.0")>0 && revcomp(a:bver, b:"13.0")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.5")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"10.0.5")<0) {
    txt += "Package libxul version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
