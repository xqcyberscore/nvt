# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0007.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122244");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:15:22 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0007");
script_tag(name: "insight", value: "ELSA-2011-0007 -  kernel security and bug fix update - [2.6.32-71.14.1.0.1.el6]- replace Red Hat with Oracle in files genkey and kernel.spec[2.6.32-71.14.1.el6]- [kvm] x86: zero kvm_vcpu_events->interrupt.pad (Marcelo Tosatti) [665471 665409] {CVE-2010-4525}[2.6.32-71.13.1.el6]email_6.RHSA-2011-0007 178L, 11970C written- [scsi] lpfc: Fixed crashes for NULL pnode dereference (Rob Evers) [660589 635733][2.6.32-71.12.1.el6]- [netdrv] igb: only use vlan_gro_receive if vlans are registered (Stefan Assmann) [652804 660192] {CVE-2010-4263}- [net] core: neighbour update Oops (Jiri Pirko) [660591 658518]- [scsi] lpfc: Set heartbeat timer off by default (Rob Evers) [660244 655935]- [scsi] lpfc: Fixed crashes for BUG_ONs hit in the lpfc_abort_handler (Rob Evers) [659611 645882][2.6.32-71.11.1.el6]- [kernel] posix-cpu-timers: workaround to suppress the problems with mt exec (Oleg Nesterov) [656267 656268] {CVE-2010-4248}- [fs] bio: take care not overflow page count when mapping/copying user data (Danny Feng) [652530 652531] {CVE-2010-4162}- [net] can-bcm: fix minor heap overflow (Danny Feng) [651846 651847] {CVE-2010-3874}- [net] filter: make sure filters dont read uninitialized memory (Jiri Pirko) [651704 651705] {CVE-2010-4158}- [net] inet_diag: Make sure we actually run the same bytecode we audited (Jiri Pirko) [651268 651269] {CVE-2010-3880}- [v4l] ivtvfb: prevent reading uninitialized stack memory (Mauro Carvalho Chehab) [648832 648833] {CVE-2010-4079}- [drm] via/ioctl.c: prevent reading uninitialized stack memory (Dave Airlie) [648718 648719] {CVE-2010-4082}- [char] nozomi: clear data before returning to userspace on TIOCGICOUNT (Mauro Carvalho Chehab) [648705 648706] {CVE-2010-4077}- [serial] clean data before filling it on TIOCGICOUNT (Mauro Carvalho Chehab) [648702 648703] {CVE-2010-4075}- [net] af_unix: limit unix_tot_inflight (Neil Horman) [656761 656762] {CVE-2010-4249}- [block] check for proper length of iov entries in blk_rq_map_user_iov() (Danny Feng) [652958 652959] {CVE-2010-4163}- [net] Limit sendto()/recvfrom()/iovec total length to INT_MAX (Jiri Pirko) [651894 651895] {CVE-2010-4160}- [netdrv] mlx4: Add OFED-1.5.2 patch to increase log_mtts_per_seg (Jay Fenlason) [643815 637284]- [kernel] kbuild: fix external module compiling (Aristeu Rozanski) [658879 655231]- [net] bluetooth: Fix missing NULL check (Jarod Wilson) [655667 655668] {CVE-2010-4242}- [kernel] ipc: initialize structure memory to zero for compat functions (Danny Feng) [648694 648695] {CVE-2010-4073}- [kernel] shm: fix information leak to userland (Danny Feng) [648688 648689] {CVE-2010-4072}- [md] dm: remove extra locking when changing device size (Mike Snitzer) [653900 644380]- [block] read i_size with i_size_read() (Mike Snitzer) [653900 644380]- [kbuild] don't sign out-of-tree modules (Aristeu Rozanski) [655122 653507][2.6.32-71.10.1.el6]- [fs] xfs: prevent reading uninitialized stack memory (Dave Chinner) [630808 630809] {CVE-2010-3078}- [net] fix rds_iovec page count overflow (Jiri Pirko) [647423 647424] {CVE-2010-3865}- [scsi] Fix megaraid_sas driver SLAB memory leak detected with CONFIG_DEBUG_SLAB (Shyam Iyer) [649436 633836]- [usb] serial/mos*: prevent reading uninitialized stack memory (Don Zickus) [648697 648698] {CVE-2010-4074}- [kernel] ecryptfs_uid_hash() buffer overflow (Jerome Marchand) [626320 611388] {CVE-2010-2492}- [sound] seq/oss - Fix double-free at error path of snd_seq_oss_open() (Jaroslav Kysela) [630554 630555] {CVE-2010-3080}- [virt] virtio-net: init link state correctly (Jason Wang) [653340 646369]- [netdrv] prevent reading uninitialized memory in hso driver (Thomas Graf) [633143 633144] {CVE-2010-3298}[2.6.32-71.9.1.el6]- [fs] Do not mix FMODE_ and O_ flags with break_lease() and may_open() (Harshula Jayasuriya) [648408 642677]- [fs] aio: check for multiplication overflow in do_io_submit (Jeff Moyer) [629450 629451] {CVE-2010-3067}- [net] fix info leak from kernel in ethtool operation (Neil Horman) [646727 646728] {CVE-2010-3861}- [net] packet: fix information leak to userland (Jiri Pirko) [649899 649900] {CVE-2010-3876}- [net] clean up info leak in act_police (Neil Horman) [636393 636394] {CVE-2010-3477}- [mm] Prevent Out Of Memory when changing cpuset's mems on NUMA (Larry Woodman) [651996 597127][2.6.32-71.8.1.el6]- [mm] remove false positive THP pmd_present BUG_ON (Andrea Arcangeli) [647391 646384][2.6.32-71.7.1.el6]- [drm] ttm: fix regression introduced in dfb4a4250168008c5ac61e90ab2b86f074a83a6c (Dave Airlie) [646994 644896][2.6.32-71.6.1.el6]- [block] fix a potential oops for callers of elevator_change (Jeff Moyer) [644926 641408][2.6.32-71.5.1.el6]- [security] IMA: require command line option to enabled (Eric Paris) [644636 643667]- [net] Fix priv escalation in rds protocol (Neil Horman) [642899 642900] {CVE-2010-3904}- [v4l] Remove compat code for VIDIOCSMICROCODE (Mauro Carvalho Chehab) [642472 642473] {CVE-2010-2963}- [kernel] tracing: do not allow llseek to set_ftrace_filter (Jiri Olsa) [631625 631626] {CVE-2010-3079}- [virt] xen: hold mm->page_table_lock in vmalloc_sync (Andrew Jones) [644038 643371]- [fs] xfs: properly account for reclaimed inodes (Dave Chinner) [642680 641764]- [drm] fix ioctls infoleak (Danny Feng) [626319 621437] {CVE-2010-2803}- [netdrv] wireless extensions: fix kernel heap content leak (John Linville) [628437 628438] {CVE-2010-2955}- [netdrv] niu: buffer overflow for ETHTOOL_GRXCLSRLALL (Danny Feng) [632071 632072] {CVE-2010-3084}- [mm] add debug checks for mapcount related invariants (Andrea Arcangeli) [642679 622327 644037 642570]- [mm] move VM_BUG_ON inside the page_table_lock of zap_huge_pmd (Andrea Arcangeli) [642679 622327 644037 642570]- [mm] compaction: handle active and inactive fairly in too_many_isolated (Andrea Arcangeli) [642679 622327 644037 642570]- [mm] start_khugepaged after setting transparent_hugepage_flags (Andrea Arcangeli) [642679 622327 644037 642570]- [mm] fix hibernate memory corruption (Andrea Arcangeli) [644037 642570]- [mm] ksmd wait_event_freezable (Andrea Arcangeli) [642679 622327 644037 642570]- [mm] khugepaged wait_event_freezable (Andrea Arcangeli) [642679 622327 644037 642570]- [mm] unlink_anon_vmas in __split_vma in case of error (Andrea Arcangeli) [642679 622327 644037 642570]- [mm] fix memleak in copy_huge_pmd (Andrea Arcangeli) [642679 622327 644037 642570]- [mm] fix hang on anon_vma->root->lock (Andrea Arcangeli) [642679 622327 644037 642570]- [mm] avoid breaking huge pmd invariants in case of vma_adjust failures (Andrea Arcangeli) [642679 622327 644037 642570][2.6.32-71.4.1.el6]- [scsi] fcoe: set default FIP mode as FIP_MODE_FABRIC (Mike Christie) [641457 636233]- [virt] KVM: Fix fs/gs reload oops with invalid ldt (Avi Kivity) [639884 639885] {CVE-2010-3698}- [drm] i915: prevent arbitrary kernel memory write (Jerome Marchand) [637690 637691] {CVE-2010-2962}- [scsi] libfc: adds flogi retry in case DID is zero in RJT (Mike Christie) [641456 633907]- [kernel] prevent heap corruption in snd_ctl_new() (Jerome Marchand) [638485 638486] {CVE-2010-3442}- [scsi] lpfc: lpfc driver oops during rhel6 installation with snapshot 12/13 and emulex FC (Rob Evers) [641907 634703]- [fs] ext4: Always journal quota file modifications (Eric Sandeen) [641454 624909]- [mm] fix split_huge_page error like mapcount 3 page_mapcount 2 (Andrea Arcangeli) [641258 640611]- [block] Fix pktcdvd ioctl dev_minor range check (Jerome Marchand) [638088 638089] {CVE-2010-3437}- [drm] ttm: Fix two race conditions + fix busy codepaths (Dave Airlie) [642045 640871]- [drm] Prune GEM vma entries (Dave Airlie) [642043 640870]- [virt] ksm: fix bad user data when swapping (Andrea Arcangeli) [641459 640579]- [virt] ksm: fix page_address_in_vma anon_vma oops (Andrea Arcangeli) [641460 640576]- [net] sctp: Fix out-of-bounds reading in sctp_asoc_get_hmac() (Jiri Pirko) [640461 640462] {CVE-2010-3705}- [mm] Move vma_stack_continue into mm.h (Mike Snitzer) [641483 638525]- [net] sctp: Do not reset the packet during sctp_packet_config() (Jiri Pirko) [637681 637682] {CVE-2010-3432}- [mm] vmstat incorrectly reports disk IO as swap in (Steve Best) [641458 636978]- [scsi] fcoe: Fix NPIV (Neil Horman) [641455 631246][2.6.32-71.3.1.el6]- [block] prevent merges of discard and write requests (Mike Snitzer) [639412 637805]- [drm] nouveau: correct INIT_DP_CONDITION subcondition 5 (Ben Skeggs) [638973 636678]- [drm] nouveau: enable enhanced framing only if DP display supports it (Ben Skeggs) [638973 636678]- [drm] nouveau: fix required mode bandwidth calculation for DP (Ben Skeggs) [638973 636678]- [drm] nouveau: disable hotplug detect around DP link training (Ben Skeggs) [638973 636678]- [drm] nouveau: set DP display power state during DPMS (Ben Skeggs) [638973 636678]- [mm] remove madvise from possible /sys/kernel/mm/redhat_transparent_hugepage/enabled options (Larry Woodman) [636116 634500]- [netdrv] cxgb3: don't flush the workqueue if we are called from the workqueue (Doug Ledford) [634973 631547]- [netdrv] cxgb3: deal with fatal parity error status in interrupt handler (Doug Ledford) [634973 631547]- [netdrv] cxgb3: now that we define fatal parity errors, make sure they are cleared (Doug Ledford) [634973 631547]- [netdrv] cxgb3: Add define for fatal parity error bit manipulation (Doug Ledford) [634973 631547]- [virt] Emulate MSR_EBC_FREQUENCY_ID (Jes Sorensen) [633966 629836]- [virt] Define MSR_EBC_FREQUENCY_ID (Jes Sorensen) [633966 629836]- [kernel] initramfs: Fix initramfs size calculation (Hendrik Brueckner) [637087 626956]- [kernel] initramfs: Generalize initramfs_data.xxx.S variants (Hendrik Brueckner) [637087 626956]- [drm] radeon/kms: fix sideport detection on newer rs880 boards (Dave Airlie) [634984 626454]- [block] switch s390 tape_block and mg_disk to elevator_change() (Mike Snitzer) [633864 632631]- [block] add function call to switch the IO scheduler from a driver (Mike Snitzer) [633864 632631][2.6.32-71.2.1.el6]- [misc] make compat_alloc_user_space() incorporate the access_ok() (Xiaotian Feng) [634465 634466] {CVE-2010-3081}- [x86] kernel: fix IA32 System Call Entry Point Vulnerability (Xiaotian Feng) [634451 634452] {CVE-2010-3301}[2.6.32-71.1.1.el6]- [security] Make kernel panic in FIPS mode if modsign check fails (David Howells) [633865 625914]- [virt] Guests on AMD with CPU type 6 and model >= 8 trigger errata read of MSR_K7_CLK_CTL (Jes Sorensen) [632292 629066]- [x86] UV: use virtual efi on SGI systems (George Beshers) [633964 627653]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0007");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0007.html");
script_cve_id("CVE-2010-2492","CVE-2010-2803","CVE-2010-2955","CVE-2010-2962","CVE-2010-3067","CVE-2010-3078","CVE-2010-3079","CVE-2010-3080","CVE-2010-3081","CVE-2010-3084","CVE-2010-3298","CVE-2010-3301","CVE-2010-3432","CVE-2010-3437","CVE-2010-3442","CVE-2010-3477","CVE-2010-3698","CVE-2010-3705","CVE-2010-3861","CVE-2010-3865","CVE-2010-3874","CVE-2010-3876","CVE-2010-3880","CVE-2010-3904","CVE-2010-4072","CVE-2010-4073","CVE-2010-4074","CVE-2010-4075","CVE-2010-4077","CVE-2010-4079","CVE-2010-4080","CVE-2010-4081","CVE-2010-4082","CVE-2010-4083","CVE-2010-4158","CVE-2010-4160","CVE-2010-4162","CVE-2010-4163","CVE-2010-4242","CVE-2010-4248","CVE-2010-4249","CVE-2010-4263","CVE-2010-4525","CVE-2010-4668");
script_tag(name:"cvss_base", value:"8.3");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~71.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~71.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~71.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~71.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~71.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~71.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~71.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~71.14.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

