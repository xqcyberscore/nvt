#
#VID 3c7d565a-6c64-11e0-813a-6c626dd55a41
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 3c7d565a-6c64-11e0-813a-6c626dd55a41
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
   asterisk14
   asterisk16
   asterisk18

CVE-2011-1507
Asterisk Open Source 1.4.x before 1.4.40.1, 1.6.1.x before 1.6.1.25,
1.6.2.x before 1.6.2.17.3, and 1.8.x before 1.8.3.3 and Asterisk
Business Edition C.x.x before C.3.6.4 do not restrict the number of
unauthenticated sessions to certain interfaces, which allows remote
attackers to cause a denial of service (file descriptor exhaustion and
disk space exhaustion) via a series of TCP connections.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://downloads.asterisk.org/pub/security/AST-2011-005.pdf
http://downloads.asterisk.org/pub/security/AST-2011-006.pdf
http://www.vuxml.org/freebsd/3c7d565a-6c64-11e0-813a-6c626dd55a41.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";




if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.69591");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2011-1507");
 script_name("FreeBSD Ports: asterisk14");



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
bver = portver(pkg:"asterisk14");
if(!isnull(bver) && revcomp(a:bver, b:"1.4")>0 && revcomp(a:bver, b:"1.4.40.1")<0) {
    txt += 'Package asterisk14 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"asterisk16");
if(!isnull(bver) && revcomp(a:bver, b:"1.6")>0 && revcomp(a:bver, b:"1.6.2.17.3")<0) {
    txt += 'Package asterisk16 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"asterisk18");
if(!isnull(bver) && revcomp(a:bver, b:"1.8")>0 && revcomp(a:bver, b:"1.8.3.3")<0) {
    txt += 'Package asterisk18 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
