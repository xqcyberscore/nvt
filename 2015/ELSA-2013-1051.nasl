# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1051.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.com> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.com
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
script_oid("1.3.6.1.4.1.25623.1.0.123597");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:02 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1051");
script_tag(name: "insight", value: "ELSA-2013-1051 -  kernel security and bug fix update - [2.6.32-358.14.1]- [x86] apic: Add probe() for apic_flat (Prarit Bhargava) [975086 953342][2.6.32-358.13.1]- [wireless] b43: stop format string leaking into error msgs (John Linville) [971387 971389] {CVE-2013-2852}- [pci] make sriov work with hotplug remove (Takahiro MUNEDA) [973555 965002]- [net] rtnl: fix info leak on RTM_GETLINK request for VF devices (Flavio Leitner) [923657 923659] {CVE-2013-2634 CVE-2013-2635}- [net] dcbnl: fix various netlink info leaks (Flavio Leitner) [923657 923659] {CVE-2013-2634 CVE-2013-2635}- [net] bonding: fix enslaving in alb mode when link down (Veaceslav Falico) [969306 965132]- [net] tcp: Fix oops from tcp_collapse() when using splice() (Nikola Pajkovsky) [968871 863512] {CVE-2013-2128}- [usb] uhci: fix IRQ race during initialization (Dave Young) [968557 915834]- [netdrv] e1000e: enable VLAN RX/TX in PROMISC mode (Stefan Assmann) [963564 886420]- [netdrv] bnx2x: strip VLAN header in PROMISC mode (Stefan Assmann) [963564 886420]- [net] vlan: handle packets with empty vlan_group via VLAN code (Stefan Assmann) [963564 886420]- [fs] namei.c: Dont allow to create hardlink for deleted file (Brian Foster) [956296 908158]- [fs] gfs2: Reinstate withdraw ack system (Robert S Peterson) [927308 908093]- [fs] nfs: open a file descriptor for fsync in nfs4 recovery (J. Bruce Fields) [964046 915479]- [net] macvlan: remove bogus check in macvlan_handle_frame() (Jiri Pirko) [962370 952785]- [net] macvlan: fix passthru mode race between dev removal and rx path (Jiri Pirko) [962370 952785]- [kernel] rcu: Replace list_first_entry_rcu() with list_first_or_null_rcu() (Jiri Pirko) [962370 952785]- [net] bluetooth/rfcomm: Fix missing msg_namelen update in rfcomm_sock_recvmsg() (Weiping Pan) [955653 955654] {CVE-2013-3225}- [net] bluetooth: fix possible info leak in bt_sock_recvmsg() (Radomir Vrbovsky) [955603 955604] {CVE-2013-3224}- [fs] gfs2: Issue discards in 512b sectors (Robert S Peterson) [927317 922779]- [fs] udf: avoid info leak on export (Nikola Pajkovsky) [922354 922355] {CVE-2012-6548}- [scsi] lpfc: Fixed deadlock between hbalock and nlp_lock use (Rob Evers) [962368 960717]- [kernel] tracing: Fix possible NULL pointer dereferences (Weiping Pan) [952212 952213] {CVE-2013-3301}- [kernel] tracing: Fix panic when lseek() called on 'trace' opened for writing (Weiping Pan) [952212 952213] {CVE-2013-3301}- [net] atm: update msg_namelen in vcc_recvmsg() (Nikola Pajkovsky) [955224 955225] {CVE-2013-3222}- [x86] apic: Work around boot failure on HP ProLiant DL980 G7 Server systems (Prarit Bhargava) [969326 912963]- [x86] apic: Use probe routines to simplify apic selection (Prarit Bhargava) [969326 912963]- [x86] x2apic: Simplify apic init in SMP and UP builds (Prarit Bhargava) [969326 912963]- [kvm] vmx: provide the vmclear function and a bitmap to support VMCLEAR in kdump (Andrew Jones) [962372 908608]- [x86] kexec: VMCLEAR VMCSs loaded on all cpus if necessary (Andrew Jones) [962372 908608]- [fs] ext3: Fix format string issues (Nikola Pajkovsky) [920784 920785] {CVE-2013-1848}- [kernel] signal: always clear sa_restorer on execve (Nikola Pajkovsky) [920505 920506] {CVE-2013-0914}[2.6.32-358.12.1]- [fs] Panic in gfs2_inplace_reserve after fix from BZ#875753 (Robert S Peterson) [924847 922999]- [nfs] sunrpc: Prevent an rpc_task wakeup race (Dave Wysochanski) [956979 840860]- [nfs] sunrpc: clarify comments on rpc_make_runnable (Dave Wysochanski) [956979 840860]- [x86] acpi: Avoid SRAT table checks for Fujitsu Primequest systems (Prarit Bhargava) [973198 966853]- [x86] oprofile: Fix crash when unloading module in nmi timer mode (Don Zickus) [972586 828936]- [block] propagate proper return codes from blk_get_request callers (Jeff Moyer) [958684 927918]- [block] Check the return value from blk_get_request (Jeff Moyer) [958684 927918]- [virt] kvm/mmu: fix hashing for TDP and non-paging modes (Marcelo Tosatti) [966432 908751]- [virt] kvm/mmu: Fix free memory accounting race in mmu_alloc_roots() (Marcelo Tosatti) [966432 908751]- [virt] kvm/mmu: Don't flush shadow when enabling dirty tracking (Marcelo Tosatti) [966432 908751]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1051");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1051.html");
script_cve_id("CVE-2013-1848","CVE-2013-0914","CVE-2013-3222","CVE-2013-3224","CVE-2012-6548","CVE-2013-2128","CVE-2013-2634","CVE-2013-2635","CVE-2013-3225","CVE-2013-3301","CVE-2013-2852");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_tag(name:"qod_type", value:"package");
script_dependencies("gather-package-list.nasl");
script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release");
script_category(ACT_GATHER_INFO);
script_copyright("Eero Volotinen");
script_family("Oracle Linux Local Security Checks");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

