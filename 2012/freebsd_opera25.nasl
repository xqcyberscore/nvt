#
#VID a4a809d8-25c8-11e1-b531-00215c6a37bb
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID a4a809d8-25c8-11e1-b531-00215c6a37bb
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
   opera
   linux-opera
   opera-devel

CVE-2011-3389
The SSL protocol, as used in certain configurations in Microsoft
Windows and Microsoft Internet Explorer, Mozilla Firefox, Google
Chrome, Opera, and other products, encrypts data by using CBC mode
with chained initialization vectors, which allows man-in-the-middle
attackers to obtain plaintext HTTP headers via a blockwise
chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with
JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java
URLConnection API, or (3) the Silverlight WebClient API, aka a 'BEAST'
attack.

CVE-2011-4681
Opera before 11.60 does not properly consider the number of . (dot)
characters that conventionally exist in domain names of different
top-level domains, which allows remote attackers to bypass the Same
Origin Policy by leveraging access to a different domain name in the
same top-level domain, as demonstrated by the .no or .uk domain.

CVE-2011-4682
The JavaScript engine in Opera before 11.60 does not properly
implement the in operator, which allows remote attackers to bypass the
Same Origin Policy via vectors related to variables on different web
sites.

CVE-2011-4683
Unspecified vulnerability in Opera before 11.60 has unknown impact and
attack vectors, related to a 'moderately severe issue.'";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.opera.com/support/kb/view/1003/
http://www.opera.com/support/kb/view/1004/
http://www.opera.com/support/kb/view/1005/
http://www.vuxml.org/freebsd/a4a809d8-25c8-11e1-b531-00215c6a37bb.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70592");
 script_tag(name:"creation_date", value:"2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-3389", "CVE-2011-4681", "CVE-2011-4682", "CVE-2011-4683");
 script_version("$Revision: 9352 $");
 script_name("FreeBSD Ports: opera, linux-opera");

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
bver = portver(pkg:"opera");
if(!isnull(bver) && revcomp(a:bver, b:"11.60")<0) {
    txt += 'Package opera version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-opera");
if(!isnull(bver) && revcomp(a:bver, b:"11.60")<0) {
    txt += 'Package linux-opera version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"opera-devel");
if(!isnull(bver) && revcomp(a:bver, b:"11.60,1")<0) {
    txt += 'Package opera-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
