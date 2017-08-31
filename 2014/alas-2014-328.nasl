# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2014-328.nasl 6663 2017-07-11 09:58:05Z teissa $
 
# Authors: 
# Eero Volotinen <eero.volotinen@iki.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
if(description)
 {
script_oid("1.3.6.1.4.1.25623.1.0.120205");
script_version("$Revision: 6663 $");
script_tag(name:"creation_date", value:"2015-09-08 13:20:06 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2014-328");
script_tag(name: "insight", value: "The ip6_route_add function in net/ipv6/route.c in the Linux kernel through 3.13.6 does not properly count the addition of routes, which allows remote attackers to cause a denial of service (memory consumption) via a flood of ICMPv6 Router Advertisement packets.drivers/vhost/net.c in the Linux kernel before 3.13.10, when mergeable buffers are disabled, does not properly validate packet lengths, which allows guest OS users to cause a denial of service (memory corruption and host OS crash) or possibly gain privileges on the host OS via crafted packets, related to the handle_rx and get_rx_bufs functions.net/netfilter/nf_conntrack_proto_dccp.c in the Linux kernel through 3.13.6 uses a DCCP header pointer incorrectly, which allows remote attackers to cause a denial of service (system crash) or possibly execute arbitrary code via a DCCP packet that triggers a call to the (1) dccp_new, (2) dccp_packet, or (3) dccp_error function.The get_rx_bufs function in drivers/vhost/net.c in the vhost-net subsystem in the Linux kernel package before 2.6.32-431.11.2 on Red Hat Enterprise Linux (RHEL) 6 does not properly handle vhost_get_vq_desc errors, which allows guest OS users to cause a denial of service (host OS crash) via unspecified vectors."); 
script_tag(name : "solution", value : "Run yum update kernel to update your system.  You will need to reboot your system in order for the new kernel to be running.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2014-328.html");
script_cve_id("CVE-2014-2309", "CVE-2014-0077", "CVE-2014-2523", "CVE-2014-0055");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
script_copyright("Eero Volotinen");
script_family("Amazon Linux Local Security Checks");
exit(0);
}
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");
release = get_kb_item("ssh/login/release");
res = "";
if(release == NULL)
{
 exit(0);
}
if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.37~47.135.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~3.10.37~47.135.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.37~47.135.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.37~47.135.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~3.10.37~47.135.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.37~47.135.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.37~47.135.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
