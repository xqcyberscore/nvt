#
#VID dbf338d0-dce5-11e1-b655-14dae9ebcf89
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID dbf338d0-dce5-11e1-b655-14dae9ebcf89
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

CVE-2012-1949
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 4.x through 13.0, Thunderbird 5.0 through 13.0, and SeaMonkey
before 2.11 allow remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute
arbitrary code via unknown vectors.
CVE-2012-1950
The drag-and-drop implementation in Mozilla Firefox 4.x through 13.0
and Firefox ESR 10.x before 10.0.6 allows remote attackers to spoof
the address bar by canceling a page load.
CVE-2012-1951
Use-after-free vulnerability in the nsSMILTimeValueSpec::IsEventBased
function in Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x before
10.0.6, Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x before
10.0.6, and SeaMonkey before 2.11 allows remote attackers to cause a
denial of service (heap memory corruption) or possibly execute
arbitrary code by interacting with objects used for SMIL Timing.
CVE-2012-1952
The nsTableFrame::InsertFrames function in Mozilla Firefox 4.x through
13.0, Firefox ESR 10.x before 10.0.6, Thunderbird 5.0 through 13.0,
Thunderbird ESR 10.x before 10.0.6, and SeaMonkey before 2.11 does not
properly perform a cast of a frame variable during processing of mixed
row-group and column-group frames, which might allow remote attackers
to execute arbitrary code via a crafted web site.
CVE-2012-1953
The ElementAnimations::EnsureStyleRuleFor function in Mozilla Firefox
4.x through 13.0, Firefox ESR 10.x before 10.0.6, Thunderbird 5.0
through 13.0, Thunderbird ESR 10.x before 10.0.6, and SeaMonkey before
2.11 allows remote attackers to cause a denial of service (buffer
over-read, incorrect pointer dereference, and heap-based buffer
overflow) or possibly execute arbitrary code via a crafted web site.
CVE-2012-1954
Use-after-free vulnerability in the nsDocument::AdoptNode function in
Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x before 10.0.6,
Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x before 10.0.6, and
SeaMonkey before 2.11 allows remote attackers to cause a denial of
service (heap memory corruption) or possibly execute arbitrary code
via vectors involving multiple adoptions and empty documents.
CVE-2012-1955
Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x before 10.0.6,
Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x before 10.0.6, and
SeaMonkey before 2.11 allow remote attackers to spoof the address bar
via vectors involving history.forward and history.back calls.
CVE-2012-1957
An unspecified parser-utility class in Mozilla Firefox 4.x through
13.0, Firefox ESR 10.x before 10.0.6, Thunderbird 5.0 through 13.0,
Thunderbird ESR 10.x before 10.0.6, and SeaMonkey before 2.11 does not
properly handle EMBED elements within description elements in RSS
feeds, which allows remote attackers to conduct cross-site scripting
(XSS) attacks via a feed.
CVE-2012-1958
Use-after-free vulnerability in the nsGlobalWindow::PageHidden
function in Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x before
10.0.6, Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x before
10.0.6, and SeaMonkey before 2.11 might allow remote attackers to
execute arbitrary code via vectors related to focused content.
CVE-2012-1959
Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x before 10.0.6,
Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x before 10.0.6, and
SeaMonkey before 2.11 do not consider the presence of same-compartment
security wrappers (SCSW) during the cross-compartment wrapping of
objects, which allows remote attackers to bypass intended XBL access
restrictions via crafted content.
CVE-2012-1960
The qcms_transform_data_rgb_out_lut_sse2 function in the QCMS
implementation in Mozilla Firefox 4.x through 13.0, Thunderbird 5.0
through 13.0, and SeaMonkey before 2.11 might allow remote attackers
to obtain sensitive information from process memory via a crafted
color profile that triggers an out-of-bounds read operation.
CVE-2012-1961
Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x before 10.0.6,
Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x before 10.0.6, and
SeaMonkey before 2.11 do not properly handle duplicate values in
X-Frame-Options headers, which makes it easier for remote attackers to
conduct clickjacking attacks via a FRAME element referencing a web
site that produces these duplicate values.
CVE-2012-1962
Use-after-free vulnerability in the JSDependentString::undepend
function in Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x before
10.0.6, Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x before
10.0.6, and SeaMonkey before 2.11 allows remote attackers to cause a
denial of service (memory corruption) or possibly execute arbitrary
code via vectors involving strings with multiple dependencies.
CVE-2012-1963
The Content Security Policy (CSP) functionality in Mozilla Firefox 4.x
through 13.0, Firefox ESR 10.x before 10.0.6, Thunderbird 5.0 through
13.0, Thunderbird ESR 10.x before 10.0.6, and SeaMonkey before 2.11
does not properly restrict the strings placed into the blocked-uri
parameter of a violation report, which allows remote web servers to
capture OpenID credentials and OAuth 2.0 access tokens by triggering a
violation.
CVE-2012-1964
The certificate-warning functionality in
browser/components/certerror/content/aboutCertError.xhtml in Mozilla
Firefox 4.x through 12.0, Firefox ESR 10.x before 10.0.6, Thunderbird
5.0 through 12.0, Thunderbird ESR 10.x before 10.0.6, and SeaMonkey
before 2.10 does not properly handle attempted clickjacking of the
about:certerror page, which allows man-in-the-middle attackers to
trick users into adding an unintended exception via an IFRAME element.
CVE-2012-1965
Mozilla Firefox 4.x through 13.0 and Firefox ESR 10.x before 10.0.6 do
not properly establish the security context of a feed: URL, which
allows remote attackers to bypass unspecified cross-site scripting
(XSS) protection mechanisms via a feed:javascript: URL.
CVE-2012-1966
Mozilla Firefox 4.x through 13.0 and Firefox ESR 10.x before 10.0.6 do
not have the same context-menu restrictions for data: URLs as for
javascript: URLs, which allows remote attackers to conduct cross-site
scripting (XSS) attacks via a crafted URL.
CVE-2012-1967
Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x before 10.0.6,
Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x before 10.0.6, and
SeaMonkey before 2.11 do not properly implement the JavaScript sandbox
utility, which allows remote attackers to execute arbitrary JavaScript
code with improper privileges via a javascript: URL.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/security/known-vulnerabilities/
http://www.mozilla.org/security/announce/2012/mfsa2012-42.html
http://www.mozilla.org/security/announce/2012/mfsa2012-43.html
http://www.mozilla.org/security/announce/2012/mfsa2012-44.html
http://www.mozilla.org/security/announce/2012/mfsa2012-45.html
http://www.mozilla.org/security/announce/2012/mfsa2012-46.html
http://www.mozilla.org/security/announce/2012/mfsa2012-47.html
http://www.mozilla.org/security/announce/2012/mfsa2012-48.html
http://www.mozilla.org/security/announce/2012/mfsa2012-49.html
http://www.mozilla.org/security/announce/2012/mfsa2012-50.html
http://www.mozilla.org/security/announce/2012/mfsa2012-51.html
http://www.mozilla.org/security/announce/2012/mfsa2012-52.html
http://www.mozilla.org/security/announce/2012/mfsa2012-53.html
http://www.mozilla.org/security/announce/2012/mfsa2012-54.html
http://www.mozilla.org/security/announce/2012/mfsa2012-55.html
http://www.mozilla.org/security/announce/2012/mfsa2012-56.html
http://www.vuxml.org/freebsd/dbf338d0-dce5-11e1-b655-14dae9ebcf89.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.71511");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-1949", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967");
 script_version("$Revision: 8671 $");
 script_tag(name:"last_modification", value:"$Date: 2018-02-05 17:38:48 +0100 (Mon, 05 Feb 2018) $");
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
if(!isnull(bver) && revcomp(a:bver, b:"11.0,1")>0 && revcomp(a:bver, b:"14.0.1,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.6,1")<0) {
    txt += "Package firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.6,1")<0) {
    txt += "Package linux-firefox version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.11")<0) {
    txt += "Package linux-seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"10.0.6")<0) {
    txt += "Package linux-thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.11")<0) {
    txt += "Package seamonkey version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"11.0")>0 && revcomp(a:bver, b:"14.0")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"10.0.6")<0) {
    txt += "Package thunderbird version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"10.0.6")<0) {
    txt += "Package libxul version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
