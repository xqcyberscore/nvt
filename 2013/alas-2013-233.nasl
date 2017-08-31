# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2013-233.nasl 6577 2017-07-06 13:43:46Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120191");
script_version("$Revision: 6577 $");
script_tag(name:"creation_date", value:"2015-09-08 13:19:35 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:43:46 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2013-233");
script_tag(name: "insight", value: "The do_tkill function in kernel/signal.c in the Linux kernel before 3.8.9 does not initialize a certain data structure, which allows local users to obtain sensitive information from kernel memory via a crafted application that makes a (1) tkill or (2) tgkill system call.The udp_v6_push_pending_frames function in net/ipv6/udp.c in the IPv6 implementation in the Linux kernel through 3.10.3 makes an incorrect function call for pending data, which allows local users to cause a denial of service (BUG and system crash) via a crafted application that uses the UDP_CORK option in a setsockopt system call. net/ipv6/ip6_output.c in the Linux kernel through 3.11.4 does not properly determine the need for UDP Fragmentation Offload (UFO) processing of small packets after the UFO queueing of a large packet, which allows remote attackers to cause a denial of service (memory corruption and system crash) or possibly have unspecified other impact via network traffic that triggers a large response packet. The __request_module function in kernel/kmod.c in the Linux kernel before 3.4 does not set a certain killable attribute, which allows local users to cause a denial of service (memory consumption) via a crafted application. Interpretation conflict in drivers/md/dm-snap-persistent.c in the Linux kernel through 3.11.6 allows remote authenticated users to obtain sensitive information or modify data via a crafted mapping to a snapshot block device."); 
script_tag(name : "solution", value : "Run yum update kernel to update your system.  You will need to reboot your system in order for the new kernel to be running.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2013-233.html");
script_cve_id("CVE-2013-2141", "CVE-2013-4162", "CVE-2013-4387", "CVE-2012-4398", "CVE-2013-4299");
script_tag(name:"cvss_base", value:"6.1");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
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
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.4.66~55.43.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~3.4.66~55.43.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.4.66~55.43.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.4.66~55.43.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~3.4.66~55.43.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.4.66~55.43.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.4.66~55.43.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
