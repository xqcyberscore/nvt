###############################################################################
# OpenVAS Vulnerability Test
# $Id: freebsd_wireshark7.nasl 11762 2018-10-05 10:54:12Z cfischer $
#
# Auto generated from VID 4cdfe875-e8d6-11e1-bea0-002354ed89bc
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71843");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2012-4048", "CVE-2012-4049", "CVE-2012-4285", "CVE-2012-4286", "CVE-2012-4287", "CVE-2012-4288", "CVE-2012-4289", "CVE-2012-4290", "CVE-2012-4291", "CVE-2012-4292", "CVE-2012-4293", "CVE-2012-4294", "CVE-2012-4295", "CVE-2012-4296", "CVE-2012-4297", "CVE-2012-4298");
  script_version("$Revision: 11762 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-30 11:34:18 -0400 (Thu, 30 Aug 2012)");
  script_name("FreeBSD Ports: wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("FreeBSD Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/freebsd", "ssh/login/freebsdrel");

  script_tag(name:"insight", value:"The following packages are affected:

  wireshark
   wireshark-lite
   tshark
   tshark-lite

CVE-2012-4048
The PPP dissector in Wireshark 1.4.x before 1.4.14, 1.6.x before
1.6.9, and 1.8.x before 1.8.1 allows remote attackers to cause a
denial of service (invalid pointer dereference and application crash)
via a crafted packet, as demonstrated by a usbmon dump.
CVE-2012-4049
epan/dissectors/packet-nfs.c in the NFS dissector in Wireshark 1.4.x
before 1.4.14, 1.6.x before 1.6.9, and 1.8.x before 1.8.1 allows
remote attackers to cause a denial of service (loop and CPU
consumption) via a crafted packet.
CVE-2012-4285
The dissect_pft function in epan/dissectors/packet-dcp-etsi.c in the
DCP ETSI dissector in Wireshark 1.4.x before 1.4.15, 1.6.x before
1.6.10, and 1.8.x before 1.8.2 allows remote attackers to cause a
denial of service (divide-by-zero error and application crash) via a
zero-length message.
CVE-2012-4286
The pcapng_read_packet_block function in wiretap/pcapng.c in the
pcap-ng file parser in Wireshark 1.8.x before 1.8.2 allows
user-assisted remote attackers to cause a denial of service
(divide-by-zero error and application crash) via a crafted pcap-ng
file.
CVE-2012-4287
epan/dissectors/packet-mongo.c in the MongoDB dissector in Wireshark
1.8.x before 1.8.2 allows remote attackers to cause a denial of
service (loop and CPU consumption) via a small value for a BSON
document length.
CVE-2012-4288
Integer overflow in the dissect_xtp_ecntl function in
epan/dissectors/packet-xtp.c in the XTP dissector in Wireshark 1.4.x
before 1.4.15, 1.6.x before 1.6.10, and 1.8.x before 1.8.2 allows
remote attackers to cause a denial of service (loop or application
crash) via a large value for a span length.
CVE-2012-4289
epan/dissectors/packet-afp.c in the AFP dissector in Wireshark 1.4.x
before 1.4.15, 1.6.x before 1.6.10, and 1.8.x before 1.8.2 allows
remote attackers to cause a denial of service (loop and CPU
consumption) via a large number of ACL entries.
CVE-2012-4290
The CTDB dissector in Wireshark 1.4.x before 1.4.15, 1.6.x before
1.6.10, and 1.8.x before 1.8.2 allows remote attackers to cause a
denial of service (loop and CPU consumption) via a malformed packet.
CVE-2012-4291
The CIP dissector in Wireshark 1.4.x before 1.4.15, 1.6.x before
1.6.10, and 1.8.x before 1.8.2 allows remote attackers to cause a
denial of service (memory consumption) via a malformed packet.
CVE-2012-4292
The dissect_stun_message function in epan/dissectors/packet-stun.c in
the STUN dissector in Wireshark 1.4.x before 1.4.15, 1.6.x before
1.6.10, and 1.8.x before 1.8.2 does not properly interact with
key-destruction behavior in a certain tree library, which allows
remote attackers to cause a denial of service (application crash) via
a malformed packet.
CVE-2012-4293
plugins/ethercat/packet-ecatmb.c in the EtherCAT Mailbox dissector in
Wireshark 1.4.x before 1.4.15, 1.6.x before 1.6.10, and 1.8.x before
1.8.2 does not properly handle certain integer fields, which allows
remote attackers to cause a denial of service (application exit) via a
malformed packet.
CVE-2012-4294
Buffer overflow in the channelised_fill_sdh_g707_format function in
epan/dissectors/packet-erf.c in the ERF dissector in Wireshark 1.8.x
before 1.8.2 allows remote attackers to execute arbitrary code via a
large speed (aka rate) value.
CVE-2012-4295
Array index error in the channelised_fill_sdh_g707_format function in
epan/dissectors/packet-erf.c in the ERF dissector in Wireshark 1.8.x
before 1.8.2 might allow remote attackers to cause a denial of service
(application crash) via a crafted speed (aka rate) value.
CVE-2012-4296
Buffer overflow in epan/dissectors/packet-rtps2.c in the RTPS2
dissector in Wireshark 1.4.x before 1.4.15, 1.6.x before 1.6.10, and
1.8.x before 1.8.2 allows remote attackers to cause a denial of
service (CPU consumption) via a malformed packet.
CVE-2012-4297
Buffer overflow in the dissect_gsm_rlcmac_downlink function in
epan/dissectors/packet-gsm_rlcmac.c in the GSM RLC MAC dissector in
Wireshark 1.6.x before 1.6.10 and 1.8.x before 1.8.2 allows remote
attackers to execute arbitrary code via a malformed packet.
CVE-2012-4298
Integer signedness error in the vwr_read_rec_data_ethernet function in
wiretap/vwr.c in the Ixia IxVeriWave file parser in Wireshark 1.8.x
before 1.8.2 allows user-assisted remote attackers to execute
arbitrary code via a crafted packet-trace file that triggers a buffer
overflow.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-11.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-12.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-13.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-14.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-15.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-16.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-17.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-18.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-19.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-20.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-21.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-22.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-23.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-24.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-25.html");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/4cdfe875-e8d6-11e1-bea0-002354ed89bc.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-bsd.inc");

vuln = FALSE;
txt = "";

bver = portver(pkg:"wireshark");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.2")<0) {
  txt += "Package wireshark version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"wireshark-lite");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.2")<0) {
  txt += "Package wireshark-lite version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"tshark");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.2")<0) {
  txt += "Package tshark version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}
bver = portver(pkg:"tshark-lite");
if(!isnull(bver) && revcomp(a:bver, b:"1.8.2")<0) {
  txt += "Package tshark-lite version " + bver + " is installed which is known to be vulnerable.\n";
  vuln = TRUE;
}

if(vuln) {
  security_message(data:txt);
} else if (__pkg_match) {
  exit(99);
}