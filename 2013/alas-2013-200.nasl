# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2013-200.nasl 6577 2017-07-06 13:43:46Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120027");
script_version("$Revision: 6577 $");
script_tag(name:"creation_date", value:"2015-09-08 13:15:37 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:43:46 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2013-200");
script_tag(name: "insight", value: "Heap-based buffer overflow in the tg3_read_vpd function in drivers/net/ethernet/broadcom/tg3.c in the Linux kernel before 3.8.6 allows physically proximate attackers to cause a denial of service (system crash) or possibly execute arbitrary code via crafted firmware that specifies a long string in the Vital Product Data (VPD) data structure. Use-after-free vulnerability in the shmem_remount_fs function in mm/shmem.c in the Linux kernel before 3.7.10 allows local users to gain privileges or cause a denial of service (system crash) by remounting a tmpfs filesystem without specifying a required mpol (aka mempolicy) mount option. The vcc_recvmsg function in net/atm/common.c in the Linux kernel before 3.9-rc7 does not initialize a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call. The flush_signal_handlers function in kernel/signal.c in the Linux kernel before 3.8.4 preserves the value of the sa_restorer field across an exec operation, which makes it easier for local users to bypass the ASLR protection mechanism via a crafted application containing a sigaction system call. The llc_ui_recvmsg function in net/llc/af_llc.c in the Linux kernel before 3.9-rc7 does not initialize a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call. net/tipc/socket.c in the Linux kernel before 3.9-rc7 does not initialize a certain data structure and a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call. Buffer overflow in the VFAT filesystem implementation in the Linux kernel before 3.3 allows local users to gain privileges or cause a denial of service (system crash) via a VFAT write operation on a filesystem with the utf8 mount option, which is not properly handled during UTF-8 to UTF-16 conversion. The Bluetooth RFCOMM implementation in the Linux kernel before 3.6 does not properly initialize certain structures, which allows local users to obtain sensitive information from kernel memory via a crafted application. The Bluetooth protocol stack in the Linux kernel before 3.6 does not properly initialize certain structures, which allows local users to obtain sensitive information from kernel stack memory via a crafted application that targets the (1) L2CAP or (2) HCI implementation. The bt_sock_recvmsg function in net/bluetooth/af_bluetooth.c in the Linux kernel before 3.9-rc7 does not properly initialize a certain length variable, which allows local users to obtain sensitive information from kernel stack memory via a crafted recvmsg or recvfrom system call."); 
script_tag(name : "solution", value : "Run yum update kernel to update your system.  You will need to reboot your system in order for the new kernel to be running.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2013-200.html");
script_cve_id("CVE-2013-1929", "CVE-2013-1767", "CVE-2012-6545", "CVE-2012-6544", "CVE-2013-3224", "CVE-2013-3222", "CVE-2013-0914", "CVE-2013-3231", "CVE-2013-3235", "CVE-2013-1773");
script_tag(name:"cvss_base", value:"6.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
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
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~3.4.48~45.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~3.4.48~45.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.4.48~45.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.4.48~45.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.4.48~45.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.4.48~45.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.4.48~45.46.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
