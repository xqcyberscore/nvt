# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2013-218.nasl 6577 2017-07-06 13:43:46Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120439");
script_version("$Revision: 6577 $");
script_tag(name:"creation_date", value:"2015-09-08 13:26:23 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:43:46 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2013-218");
script_tag(name: "insight", value: "The bt_sock_recvmsg function in net/bluetooth/af_bluetooth.c in the Linux kernel before 3.9-rc7 does not properly initialize a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call.      The udf_encode_fh function in fs/udf/namei.c in the Linux kernel before 3.6 does not initialize a certain structure member, which allows local users to obtain sensitive information from kernel heap memory via a crafted application.      The ftrace implementation in the Linux kernel before 3.8.8 allows local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact by leveraging the CAP_SYS_ADMIN capability for write access to the (1) set_ftrace_pid or (2) set_graph_function file, and then making an lseek system call.      The rtnl_fill_ifinfo function in net/core/rtnetlink.c in the Linux kernel before 3.8.4 does not initialize a certain structure member, which allows local users to obtain sensitive information from kernel stack memory via a crafted application. The ip6_sk_dst_check function in net/ipv6/ip6_output.c in the Linux kernel before 3.10 allows local users to cause a denial of service (system crash) by using an AF_INET6 socket for a connection to an IPv4 interface. The tcp_read_sock function in net/ipv4/tcp.c in the Linux kernel before 2.6.34 does not properly manage skb consumption, which allows local users to cause a denial of service (system crash) via a crafted splice system call for a TCP socket. The rfcomm_sock_recvmsg function in net/bluetooth/rfcomm/sock.c in the Linux kernel before 3.9-rc7 does not initialize a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call. Format string vulnerability in the b43_request_firmware function in drivers/net/wireless/b43/main.c in the Broadcom B43 wireless driver in the Linux kernel through 3.9.4 allows local users to gain privileges by leveraging root access and including format string specifiers in an fwpostfix modprobe parameter, leading to improper construction of an error message. The (1) key_notify_sa_flush and (2) key_notify_policy_flush functions in net/key/af_key.c in the Linux kernel before 3.10 do not initialize certain structure members, which allows local users to obtain sensitive information from kernel heap memory by reading a broadcast message from the notify interface of an IPSec key_socket. The vcc_recvmsg function in net/atm/common.c in the Linux kernel before 3.9-rc7 does not initialize a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call. The flush_signal_handlers function in kernel/signal.c in the Linux kernel before 3.8.4 preserves the value of the sa_restorer field across an exec operation, which makes it easier for local users to bypass the ASLR protection mechanism via a crafted application containing a sigaction system call. net/dcb/dcbnl.c in the Linux kernel before 3.8.4 does not initialize certain structures, which allows local users to obtain sensitive information from kernel stack memory via a crafted application. fs/ext3/super.c in the Linux kernel before 3.8.4 uses incorrect arguments to functions in certain circumstances related to printk input, which allows local users to conduct format-string attacks and possibly gain privileges via a crafted application. net/ceph/auth_none.c in the Linux kernel through 3.10 allows remote attackers to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other impact via an auth_reply message that triggers an attempted build_request operation."); 
script_tag(name : "solution", value : "Run yum update kernel to update your system.  You will need to reboot your system in order for the new kernel to be running.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2013-218.html");
script_cve_id("CVE-2013-3224", "CVE-2012-6548", "CVE-2013-3301", "CVE-2013-2635", "CVE-2013-2232", "CVE-2013-2128", "CVE-2013-3225", "CVE-2013-2852", "CVE-2013-2234", "CVE-2013-3222", "CVE-2013-0914", "CVE-2013-2634", "CVE-2013-1848", "CVE-2013-1059");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.4.57~48.42.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~3.4.57~48.42.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.4.57~48.42.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.4.57~48.42.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.4.57~48.42.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.4.57~48.42.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.4.57~48.42.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
