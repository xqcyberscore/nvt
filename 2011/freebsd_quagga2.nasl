#
#VID ab9be2c8-ef91-11e0-ad5a-00215c6a37bb
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID ab9be2c8-ef91-11e0-ad5a-00215c6a37bb
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
tag_insight = "The following package is affected: quagga

CVE-2011-3323
The OSPFv3 implementation in ospf6d in Quagga before 0.99.19 allows
remote attackers to cause a denial of service (out-of-bounds memory
access and daemon crash) via a Link State Update message with an
invalid IPv6 prefix length.
CVE-2011-3324
The ospf6_lsa_is_changed function in ospf6_lsa.c in the OSPFv3
implementation in ospf6d in Quagga before 0.99.19 allows remote
attackers to cause a denial of service (assertion failure and daemon
exit) via trailing zero values in the Link State Advertisement (LSA)
header list of an IPv6 Database Description message.
CVE-2011-3325
ospf_packet.c in ospfd in Quagga before 0.99.19 allows remote
attackers to cause a denial of service (daemon crash) via (1) a 0x0a
type field in an IPv4 packet header or (2) a truncated IPv4 Hello
packet.
CVE-2011-3326
The ospf_flood function in ospf_flood.c in ospfd in Quagga before
0.99.19 allows remote attackers to cause a denial of service (daemon
crash) via an invalid Link State Advertisement (LSA) type in an IPv4
Link State Update message.
CVE-2011-3327
Heap-based buffer overflow in the ecommunity_ecom2str function in
bgp_ecommunity.c in bgpd in Quagga before 0.99.19 allows remote
attackers to cause a denial of service (daemon crash) or possibly
execute arbitrary code by sending a crafted BGP UPDATE message over
IPv4.";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";

tag_solution = "Update your system with the appropriate patches or
software upgrades.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.70412");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-10-16 23:01:53 +0200 (Sun, 16 Oct 2011)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2011-3323", "CVE-2011-3324", "CVE-2011-3325", "CVE-2011-3326", "CVE-2011-3327");
 script_name("FreeBSD Ports: quagga");



 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "insight" , value : tag_insight);
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
bver = portver(pkg:"quagga");
if(!isnull(bver) && revcomp(a:bver, b:"0.99.19")<0) {
    txt += 'Package quagga version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
