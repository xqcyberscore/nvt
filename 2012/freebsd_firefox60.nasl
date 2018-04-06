#
#VID e3ff776b-2ba6-11e1-93c6-0011856a6e37
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID e3ff776b-2ba6-11e1-93c6-0011856a6e37
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

CVE-2011-3658
The SVG implementation in Mozilla Firefox 8.0, Thunderbird 8.0, and
SeaMonkey 2.5 does not properly interact with DOMAttrModified event
handlers, which allows remote attackers to cause a denial of service
(out-of-bounds memory access) or possibly have unspecified other
impact via vectors involving removal of SVG elements.

CVE-2011-3660
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 4.x through 8.0, Thunderbird 5.0 through 8.0, and SeaMonkey
before 2.6 allow remote attackers to cause a denial of service (memory
corruption and application crash) or possibly execute arbitrary code
via vectors that trigger a compartment mismatch associated with the
nsDOMMessageEvent::GetData function, and unknown other vectors.

CVE-2011-3661
YARR, as used in Mozilla Firefox 4.x through 8.0, Thunderbird 5.0
through 8.0, and SeaMonkey before 2.6, allows remote attackers to
cause a denial of service (application crash) or possibly execute
arbitrary code via crafted JavaScript.

CVE-2011-3663
Mozilla Firefox 4.x through 8.0, Thunderbird 5.0 through 8.0, and
SeaMonkey before 2.6 allow remote attackers to capture keystrokes
entered on a web page, even when JavaScript is disabled, by using SVG
animation accessKey events within that web page.

CVE-2011-3665
Mozilla Firefox 4.x through 8.0, Thunderbird 5.0 through 8.0, and
SeaMonkey before 2.6 allow remote attackers to cause a denial of
service (application crash) or possibly have unspecified other impact
via an Ogg VIDEO element that is not properly handled after scaling.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/security/announce/2011/mfsa2011-53.html
http://www.mozilla.org/security/announce/2011/mfsa2011-54.html
http://www.mozilla.org/security/announce/2011/mfsa2011-55.html
http://www.mozilla.org/security/announce/2011/mfsa2011-56.html
http://www.mozilla.org/security/announce/2011/mfsa2011-58.html
http://www.vuxml.org/freebsd/e3ff776b-2ba6-11e1-93c6-0011856a6e37.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70588");
 script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-3658", "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2011-3665");
 script_version("$Revision: 9352 $");
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

txt = "";
vuln = 0;
bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"4.0,1")>0 && revcomp(a:bver, b:"9.0,1")<0) {
    txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"9.0,1")<0) {
    txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.6")<0) {
    txt += 'Package linux-seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"9.0")<0) {
    txt += 'Package linux-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.6")<0) {
    txt += 'Package seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>0 && revcomp(a:bver, b:"9.0")<0) {
    txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
