#
#VID dc9f8335-2b3b-11e0-a91b-00e0815b8da8
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID dc9f8335-2b3b-11e0-a91b-00e0815b8da8
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
tag_insight = "The following package is affected: isc-dhcp41-server

CVE-2011-0413
The DHCPv6 server in ISC DHCP 4.0.x and 4.1.x before 4.1.2-P1, 4.0-ESV
and 4.1-ESV before 4.1-ESV-R1, and 4.2.x before 4.2.1b1 allows remote
attackers to cause a denial of service (assertion failure and daemon
crash) by sending a message over IPv6 for a declined and abandoned
address.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.isc.org/software/dhcp/advisories/cve-2011-0413
http://www.kb.cert.org/vuls/id/686084
http://www.vuxml.org/freebsd/dc9f8335-2b3b-11e0-a91b-00e0815b8da8.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.68958");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-05 22:25:39 +0100 (Sat, 05 Mar 2011)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2011-0413");
 script_name("FreeBSD Ports: isc-dhcp41-server");



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
bver = portver(pkg:"isc-dhcp41-server");
if(!isnull(bver) && revcomp(a:bver, b:"4.1.2,1")<=0) {
    txt += 'Package isc-dhcp41-server version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
