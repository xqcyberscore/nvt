#
#VID 1fade8a3-e9e8-11e0-9580-4061862b8c22
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 1fade8a3-e9e8-11e0-9580-4061862b8c22
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
   libxul
   linux-firefox
   linux-seamonkey
   linux-thunderbird
   seamonkey
   thunderbird

CVE-2011-2372
Mozilla Firefox before 3.6.23 and 4.x through 6, Thunderbird before
7.0, and SeaMonkey before 2.4 do not prevent the starting of a
download in response to the holding of the Enter key, which allows
user-assisted remote attackers to bypass intended access restrictions
via a crafted web site.
CVE-2011-2995
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox before 3.6.23 and 4.x through 6, Thunderbird before 7.0, and
SeaMonkey before 2.4 allow remote attackers to cause a denial of
service (memory corruption and application crash) or possibly execute
arbitrary code via unknown vectors.
CVE-2011-2996
Unspecified vulnerability in the plugin API in Mozilla Firefox 3.6.x
before 3.6.23 allows remote attackers to cause a denial of service
(memory corruption and application crash) or possibly execute
arbitrary code via unknown vectors.
CVE-2011-2997
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 6, Thunderbird before 7.0, and SeaMonkey before 2.4 allow
remote attackers to cause a denial of service (memory corruption and
application crash) or possibly execute arbitrary code via unknown
vectors.
CVE-2011-2999
Mozilla Firefox before 3.6.23 and 4.x through 5, Thunderbird before
6.0, and SeaMonkey before 2.3 do not properly handle 'location' as the
name of a frame, which allows remote attackers to bypass the Same
Origin Policy via a crafted web site, a different vulnerability than
CVE-2010-0170.
CVE-2011-3000
Mozilla Firefox before 3.6.23 and 4.x through 6, Thunderbird before
7.0, and SeaMonkey before 2.4 do not properly handle HTTP responses
that contain multiple Location, Content-Length, or Content-Disposition
headers, which makes it easier for remote attackers to conduct HTTP
response splitting attacks via crafted header values.
CVE-2011-3001
Mozilla Firefox 4.x through 6, Thunderbird before 7.0, and SeaMonkey
before 2.4 do not prevent manual add-on installation in response to
the holding of the Enter key, which allows user-assisted remote
attackers to bypass intended access restrictions via a crafted web
site that triggers an unspecified internal error.
CVE-2011-3002
Almost Native Graphics Layer Engine (ANGLE), as used in Mozilla
Firefox before 7.0 and SeaMonkey before 2.4, does not validate the
return value of a GrowAtomTable function call, which allows remote
attackers to cause a denial of service (application crash) or possibly
execute arbitrary code via vectors that trigger a memory-allocation
error and a resulting buffer overflow.
CVE-2011-3003
Mozilla Firefox before 7.0 and SeaMonkey before 2.4 allow remote
attackers to cause a denial of service (application crash) or possibly
execute arbitrary code via an unspecified WebGL test case that
triggers a memory-allocation error and a resulting out-of-bounds write
operation.
CVE-2011-3004
The JSSubScriptLoader in Mozilla Firefox 4.x through 6 and SeaMonkey
before 2.4 does not properly handle XPCNativeWrappers during calls to
the loadSubScript method in an add-on, which makes it easier for
remote attackers to gain privileges via a crafted web site that
leverages certain unwrapping behavior.
CVE-2011-3005
Use-after-free vulnerability in Mozilla Firefox 4.x through 6,
Thunderbird before 7.0, and SeaMonkey before 2.4 allows remote
attackers to cause a denial of service (application crash) or possibly
execute arbitrary code via crafted OGG headers in a .ogg file.
CVE-2011-3232
YARR, as used in Mozilla Firefox before 7.0, Thunderbird before 7.0,
and SeaMonkey before 2.4, allows remote attackers to cause a denial of
service (application crash) or possibly execute arbitrary code via
crafted JavaScript.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/security/announce/2011/mfsa2011-36.html
http://www.mozilla.org/security/announce/2011/mfsa2011-37.html
http://www.mozilla.org/security/announce/2011/mfsa2011-38.html
http://www.mozilla.org/security/announce/2011/mfsa2011-39.html
http://www.mozilla.org/security/announce/2011/mfsa2011-40.html
http://www.mozilla.org/security/announce/2011/mfsa2011-41.html
http://www.mozilla.org/security/announce/2011/mfsa2011-42.html
http://www.mozilla.org/security/announce/2011/mfsa2011-43.html
http://www.mozilla.org/security/announce/2011/mfsa2011-44.html
http://www.mozilla.org/security/announce/2011/mfsa2011-45.html
http://www.vuxml.org/freebsd/1fade8a3-e9e8-11e0-9580-4061862b8c22.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70413");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2996", "CVE-2011-2997", "CVE-2011-2999", "CVE-2011-3000", "CVE-2011-3001", "CVE-2011-3002", "CVE-2011-3003", "CVE-2011-3004", "CVE-2011-3005", "CVE-2011-3232");
 script_name("FreeBSD Ports: firefox");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
if(!isnull(bver) && revcomp(a:bver, b:"4.0,1")>0 && revcomp(a:bver, b:"7.0,1")<0) {
    txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.6.*,1")>0 && revcomp(a:bver, b:"3.6.23,1")<0) {
    txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"1.9.2.23")<0) {
    txt += 'Package libxul version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"7.0,1")<0) {
    txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.4")<0) {
    txt += 'Package linux-seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"7.0")<0) {
    txt += 'Package linux-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"seamonkey");
if(!isnull(bver) && revcomp(a:bver, b:"2.4")<0) {
    txt += 'Package seamonkey version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>0 && revcomp(a:bver, b:"7.0")<0) {
    txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.1.15")<0) {
    txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
