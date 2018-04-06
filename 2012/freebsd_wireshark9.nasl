#
#VID a7706414-1be7-11e2-9aad-902b343deec9
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID a7706414-1be7-11e2-9aad-902b343deec9
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
   wireshark
   wireshark-lite
   tshark
   tshark-lite

CVE-2012-5237
The dissect_hsrp function in epan/dissectors/packet-hsrp.c in the HSRP
dissector in Wireshark 1.8.x before 1.8.3 allows remote attackers to
cause a denial of service (infinite loop) via a malformed packet.
CVE-2012-5238
epan/dissectors/packet-ppp.c in the PPP dissector in Wireshark 1.8.x
before 1.8.3 uses incorrect OUI data structures during the decoding of
(1) PPP and (2) LCP data, which allows remote attackers to cause a
denial of service (assertion failure and application exit) via a
malformed packet.
CVE-2012-5240
Buffer overflow in the dissect_tlv function in
epan/dissectors/packet-ldp.c in the LDP dissector in Wireshark 1.8.x
before 1.8.3 allows remote attackers to cause a denial of service
(application crash) or possibly have unspecified other impact via a
malformed packet.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.wireshark.org/security/wnpa-sec-2012-26.html
http://www.wireshark.org/security/wnpa-sec-2012-27.html
http://www.wireshark.org/security/wnpa-sec-2012-28.html
http://www.wireshark.org/security/wnpa-sec-2012-29.html
http://www.wireshark.org/docs/relnotes/wireshark-1.8.3.html
http://www.vuxml.org/freebsd/a7706414-1be7-11e2-9aad-902b343deec9.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.72500");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2012-5237", "CVE-2012-5238", "CVE-2012-5240");
 script_version("$Revision: 9352 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-10-22 08:43:21 -0400 (Mon, 22 Oct 2012)");
 script_name("FreeBSD Ports: wireshark");


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
bver = portver(pkg:"wireshark");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.2_1")<=0) {
    txt += "Package wireshark version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"wireshark-lite");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.2_1")<=0) {
    txt += "Package wireshark-lite version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"tshark");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.2_1")<=0) {
    txt += "Package tshark version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
bver = portver(pkg:"tshark-lite");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.2_1")<=0) {
    txt += "Package tshark-lite version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_message(data:string(txt ));
} else if (__pkg_match) {
    exit(99);
}
