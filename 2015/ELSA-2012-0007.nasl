# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0007.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122014");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:11:43 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0007");
script_tag(name: "insight", value: "ELSA-2012-0007 -  kernel security, bug fix, and enhancement update - [2.6.18-274.17.1.0.1.el5]- fix ia64 build error due to add-support-above-32-vcpus.patch(Zhenzhong Duan)- [x86] use dynamic vcpu_info remap to support more than 32 vcpus (Zhenzhong Duan)- [scsi] add additional scsi medium error handling (John Sobecki) [orabug 12904887]- [x86] Fix lvt0 reset when hvm boot up with noapic param- [scsi] remove printk's when doing I/O to a dead device (John Sobecki, Chris Mason) [orabug 12342275]- [char] ipmi: Fix IPMI errors due to timing problems (Joe Jin) [orabug 12561346]- [scsi] Fix race when removing SCSI devices (Joe Jin) [orabug 12404566]- bonding: reread information about speed and duplex when interface goes up (John Haxby) [orabug 11890822]- [fs] nfs: Fix __put_nfs_open_context() NULL pointer panic (Joe Jin) [orabug 12687646]- [scsi] fix scsi hotplug and rescan race [orabug 10260172]- fix filp_close() race (Joe Jin) [orabug 10335998]- make xenkbd.abs_pointer=1 by default [orabug 67188919]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- [net] Enable entropy for bnx2,bnx2x,e1000e,igb,ixgb,ixgbe,ixgbevf (John Sobecki) [orabug 10315433]- [NET] Add xen pv netconsole support (Tina Yang) [orabug 6993043] [bz 7258]- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [rds] Patch rds to 1.4.2-20 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to()- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson) [orabug 9107465]- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson) [orabug 9764220]- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]- fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro, Guru Anbalagane) [orabug 6124033]- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]- [ib] fix memory corruption (Andy Grover) [orabug 9972346]- [aio] patch removes limit on number of retries (Srinivas Eeda) [orabug 10044782]- [loop] Do not call loop_unplug for not configured loop device (orabug 10314497)[2.6.18-274.17.1.el5]- Revert: [block] add and use scsi_blk_cmd_ioctl (Paolo Bonzini) [752385 752386] {CVE-2011-4127}- Revert: [block] fail SCSI passthrough ioctls on partition devices (Paolo Bonzini) [752385 752386] {CVE-2011-4127}- Revert: [dm] do not forward ioctls from logical volumes to the underlying device (Paolo Bonzini) [752385 752386] {CVE-2011-4127}- Revert: [scsi] fix 32-on-64 block device ioctls (Paolo Bonzini) [752385 752386] {CVE-2011-4127}[2.6.18-274.16.1.el5]- [scsi] fix 32-on-64 block device ioctls (Paolo Bonzini) [752385 752386] {CVE-2011-4127}[2.6.18-274.15.1.el5]- [net] e1000e: Avoid wrong check on TX hang (Dean Nelson) [766485 746272]- [fs] xfs: Fix memory corruption in xfs_readlink (Carlos Maiolino) [749159 749160] {CVE-2011-4077}- [pci] intel-iommu: Default to non-coherent for unattached domains (Don Dutile) [766803 753924]- [fs] nfs: remove BUG() from encode_share_access() (Jeff Layton) [755442 754901] {CVE-2011-4324}- [misc] irq: Check for spurious IRQ only on disabled IRQs (Prarit Bhargava) [759387 756412]- [fs] hfs: add sanity check for file name length (Eric Sandeen) [755432 755433] {CVE-2011-4330}- [fs] proc: Fix select on /proc files without ->poll (David Howells) [755483 751214]- [fs] nfs: Ensure we mark inode as dirty if early exit from commit (Jeff Layton) [755482 714020]- [x86] apic: ack all pending irqs when crashed/on kexec (hiro muneda) [750460 742079]- [virt] kvm: fix regression w/ 32 bit KVM clock (Rik van Riel) [747875 753789 751742 731599]- [virt] kvm: fix lost tick accounting for 32 bit kvm-clock (Rik van Riel) [747875 731599]- [fs] jbd/jbd2: validate sb->s_first in journal_get_superblock (Eryu Guan) [753343 706810] {CVE-2011-4132}- [net] igb: enable link power down (Stefan Assmann) [752735 742514]- [fs] proc: fix oops on invalid /proc//maps access (Johannes Weiner) [747851 747699] {CVE-2011-3637}- [block] cciss: bump driver version (Tomas Henzl) [758024 714129]- [block] cciss: need to delay after a PCI Power Management reset (Tomas Henzl) [758024 714129]- [block] cciss: auto engage scsi susbsystem (Tomas Henzl) [758024 714129]- [block] cciss: store pdev in hba struct (Tomas Henzl) [758024 714129]- [block] cciss: use consistent variable names (Tomas Henzl) [758024 714129]- [block] cciss: add a commandline switch for simple mode (Tomas Henzl) [758024 714129]- [fs] proc: close race with exec in mem_read() (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [mm] implement access_remote_vm (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [mm] factor out main logic of access_process_vm (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [mm] use mm_struct to resolve gate vma's in __get_user_pages (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [mm] make in_gate_area take mm_struct instead of a task_struct (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [mm] make get_gate_vma take mm_struct instead of task_struct (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [x86_64] mark assoc mm when running task in 32 bit compat mode (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [misc] sched: add ctx tag to mm running task in ia32 compat mode (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [fs] proc: require the target to be tracable (or yourself) (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [fs] proc: close race in /proc/*/environ (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [fs] proc: report errors in /proc/*/*map* sanely (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [fs] proc: shift down_read(mmap_sem) to the caller (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [fs] detect exec transition phase with new mm but old creds (Johannes Weiner) [692041 692042] {CVE-2011-1020}- [net] igb: fix i350 SR-IOV failture (Stefan Assmann) [741877 714313]- [dm] do not forward ioctls from logical volumes to the underlying device (Paolo Bonzini) [752385 752386] {CVE-2011-4127}- [block] fail SCSI passthrough ioctls on partition devices (Paolo Bonzini) [752385 752386] {CVE-2011-4127}- [block] add and use scsi_blk_cmd_ioctl (Paolo Bonzini) [752385 752386] {CVE-2011-4127}- [fs] nfs: Fix an O_DIRECT Oops (Jeff Layton) [755457 754620] {CVE-2011-4325}- [net] sctp: Fix another race during accept/peeloff (Thomas Graf) [757146 714870] {CVE-2011-4348}- [scsi] isci: fix 32-bit operation when CONFIG_HIGHMEM64G=n (Phillip Lougher) [750458 713904]- [net] tg3: Only allow phy ioctls while netif_running (Phillip Lougher) [746343 683393][2.6.18-274.14.1.el5]- [input] evdev: Fix spin lock context in evdev_pass_event() (Don Zickus) [744147 734900]- [fs] dcache: Fix dentry loop detection deadlock (David Howells) [754129 717959]- [input] evdev: disable interrupts when processing events (Don Zickus) [744147 734900][2.6.18-274.13.1.el5]- [fs] dcache: Log ELOOP rather than creating a loop (David Howells) [754129 717959]- [fs] dcache: Fix loop checks in d_materialise_unique (David Howells) [754129 717959]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0007");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0007.html");
script_cve_id("CVE-2011-1020","CVE-2011-3637","CVE-2011-4077","CVE-2011-4132","CVE-2011-4324","CVE-2011-4325","CVE-2011-4330","CVE-2011-4348");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~274.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~274.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~274.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~274.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~274.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~274.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~274.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~274.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~274.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~274.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.17.1.0.1.el5~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.17.1.0.1.el5PAE~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.17.1.0.1.el5debug~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~274.17.1.0.1.el5xen~1.4.9~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.17.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.17.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.17.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~274.17.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

