# OpenVAS Vulnerability Test 
# Description: Amazon Linux security check 
# $Id: alas-2012-55.nasl 6578 2017-07-06 13:44:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.120412");
script_version("$Revision: 6578 $");
script_tag(name:"creation_date", value:"2015-09-08 13:25:46 +0200 (Tue, 08 Sep 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:44:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Amazon Linux Local Check: ALAS-2012-55");
script_tag(name: "insight", value: "A buffer overflow flaw was found in the way the Linux kernel's XFS file system implementation handled links with overly long path names. A local, unprivileged user could use this flaw to cause a denial of service or escalate their privileges by mounting a specially-crafted disk. (CVE-2011-4077 , Moderate)Flaws in ghash_update() and ghash_final() could allow a local, unprivileged user to cause a denial of service. (CVE-2011-4081 , Moderate)A flaw was found in the Linux kernel's Journaling Block Device (JBD). A local, unprivileged user could use this flaw to crash the system by mounting a specially-crafted ext3 or ext4 disk. (CVE-2011-4132 , Moderate)It was found that the kvm_vm_ioctl_assign_device() function in the KVM (Kernel-based Virtual Machine) subsystem of a Linux kernel did not check if the user requesting device assignment was privileged or not. A local, unprivileged user on the host could assign unused PCI devices, or even devices that were in use and whose resources were not properly claimed by the respective drivers, which could result in the host crashing. (CVE-2011-4347 , Moderate)Two flaws were found in the way the Linux kernel's __sys_sendmsg() function, when invoked via the sendmmsg() system call, accessed user-space memory. A local, unprivileged user could use these flaws to cause a denial of service. (CVE-2011-4594 , Moderate)A previous update introduced an integer overflow flaw in the Linux kernel. On PowerPC systems, a local, unprivileged user could use this flaw to cause a denial of service. (CVE-2011-4611 , Moderate)A flaw was found in the way the KVM subsystem of a Linux kernel handled PIT (Programmable Interval Timer) IRQs (interrupt requests) when there was no virtual interrupt controller set up. A local, unprivileged user on the host could force this situation to occur, resulting in the host crashing. (CVE-2011-4622 , Moderate)A flaw was found in the way the Linux kernel's XFS file system implementation handled on-disk Access Control Lists (ACLs). A local, unprivileged user could use this flaw to cause a denial of service or escalate their privileges by mounting a specially-crafted disk. (CVE-2012-0038 , Moderate)A flaw was found in the way the Linux kernel's KVM hypervisor implementation emulated the syscall instruction for 32-bit guests. An unprivileged guest user could trigger this flaw to crash the guest. (CVE-2012-0045 , Moderate)A divide-by-zero flaw was found in the Linux kernel's igmp_heard_query() function. An attacker able to send certain IGMP (Internet Group Management Protocol) packets to a target system could use this flaw to cause a denial of service. (CVE-2012-0207 , Moderate)"); 
script_tag(name : "solution", value : "Run yum update kernel to update your system.  You will need to reboot your system in order for the new kernel to be running.");
script_tag(name : "solution_type", value : "VendorFix");
script_xref(name : "URL" , value : "https://alas.aws.amazon.com/ALAS-2012-55.html");
script_cve_id("CVE-2011-4594", "CVE-2011-4347", "CVE-2012-0038", "CVE-2011-4622", "CVE-2012-0045", "CVE-2011-4132", "CVE-2011-4611", "CVE-2011-4081", "CVE-2011-4077", "CVE-2012-0207");
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
if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.35.14~107.1.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.35.14~107.1.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.35.14~107.1.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.35.14~107.1.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.35.14~107.1.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.35.14~107.1.39.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);
}
