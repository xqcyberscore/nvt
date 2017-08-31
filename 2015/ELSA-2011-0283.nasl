# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0283.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122239");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:15:16 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0283");
script_tag(name: "insight", value: "ELSA-2011-0283 -  kernel security, bug fix, and enhancement update - [2.6.32-71.18.1.el6]- [netdrv] ixgbe: make sure FCoE DDP user buffers are really released by the HW (Frantisek Hrbata) [674002 617193]- [netdrv] ixgbe: invalidate FCoE DDP context when no error status is available (Frantisek Hrbata) [674002 617193]- [netdrv] ixgbe: avoid doing FCoE DDP when adapter is DOWN or RESETTING (Frantisek Hrbata) [674002 617193]- [fcoe] libfc: remove tgt_flags from fc_fcp_pkt struct (Mike Christie) [666797 633915]- [fcoe] libfc: use rport timeout values for fcp recovery (Frantisek Hrbata) [666797 633915]- [fcoe] libfc: incorrect scsi host byte codes returned to scsi-ml (Mike Christie) [666797 633915]- [scsi] scsi_dh_alua: fix overflow in alua_rtpg port group id check (Mike Snitzer) [673978 670572][2.6.32-71.17.1.el6]- [s390x] kdump: allow zfcpdump to mount and write to ext4 file systems (Amerigo Wang) [661667 628676]- [scsi] qla2xxx: Properly set the return value in function qla2xxx_eh_abort (Chad Dupuis) [664398 635710]- [scsi] qla2xxx: Drop srb reference before waiting for completion (Chad Dupuis) [664398 635710]- [virt] KVM: VMX: Really clear cr0.ts when giving the guest ownership of the fpu (Avi Kivity) [658891 645898]- [virt] KVM: SVM: Initialize fpu_active in init_vmcb() (Avi Kivity) [658891 645898]- [virt] KVM: x86: Use unlazy_fpu() for host FPU (Avi Kivity) [658891 645898]- [virt] KVM: Set cr0.et when the guest writes cr0 (Avi Kivity) [658891 645898]- [virt] KVM: VMX: Give the guest ownership of cr0.ts when the fpu is active (Avi Kivity) [658891 645898]- [virt] KVM: Lazify fpu activation and deactivation (Avi Kivity) [658891 645898]- [virt] KVM: VMX: Allow the guest to own some cr0 bits (Avi Kivity) [658891 645898]- [virt] KVM: Replace read accesses of vcpu->arch.cr0 by an accessor (Avi Kivity) [658891 645898]- [virt] KVM: VMX: trace clts and lmsw instructions as cr accesses (Avi Kivity) [658891 645898][2.6.32-71.16.1.el6]- [net] ipsec: fragment locally generated tunnel-mode IPSec6 packets as needed (Herbert Xu) [670421 661113]- [net] tcp: Increase TCP_MAXSEG socket option minimum to TCP_MIN_MSS (Frantisek Hrbata) [652510 652511] {CVE-2010-4165}- [perf] perf_events: Fix perf_counter_mmap() hook in mprotect() (Oleg Nesterov) [651672 651673] {CVE-2010-4169}- [md] dm mpath: revert 'dm: Call blk_abort_queue on failed paths' (Mike Snitzer) [658854 636771]- [x86] UV: Address interrupt/IO port operation conflict (George Beshers) [662921 659480]- [mm] guard page for stacks that grow upwards (Johannes Weiner) [666796 630562]- [scsi] enable state transistions from OFFLINE to RUNNING (Mike Christie) [660590 643237]- [scsi] set queue limits no_cluster for stacked devices (Mike Snitzer) [662050 658293]- [mm] Out-of-memory under memory cgroup can call both of oom-killer-for-memcg and oom-killer-for-page-fault (Larry Woodman) [661732 592879]- [scsi] libfc: possible race could panic system due to NULL fsp->cmd (Mike Christie) [662049 638297]- [kernel] exec: copy-and-paste the fixes into compat_do_execve() paths (Oleg Nesterov) [627811 625695] {CVE-2010-4243}- [kernel] exec: make argv/envp memory visible to oom-killer (Oleg Nesterov) [627811 625695] {CVE-2010-4243}- [virt] virtio: console: Send SIGIO in case of port unplug (Amit Shah) [652720 624628]- [virt] virtio: console: Send SIGIO on new data arrival on ports (Amit Shah) [652720 624628]- [virt] virtio: console: Send SIGIO to processes that request it for host events (Amit Shah) [652720 624628]- [virt] virtio: console: Reference counting portdev structs is not needed (Amit Shah) [662721 628805]- [virt] virtio: console: Add reference counting for port struct (Amit Shah) [662721 628805]- [virt] virtio: console: Use cdev_alloc() instead of cdev_init() (Amit Shah) [662721 628805]- [virt] virtio: console: Add a find_port_by_devt() function (Amit Shah) [662721 628805]- [virt] virtio: console: Add a list of portdevs that are active (Amit Shah) [662721 628805]- [virt] virtio: console: open: Use a common path for error handling (Amit Shah) [662721 628805]- [virt] virtio: console: remove_port() should return void (Amit Shah) [662721 628805]- [virt] virtio: console: Make write() return -ENODEV on hot-unplug (Amit Shah) [662721 628805]- [virt] virtio: console: Make read() return -ENODEV on hot-unplug (Amit Shah) [662721 628805]- [virt] virtio: console: Unblock poll on port hot-unplug (Amit Shah) [662721 628805]- [virt] virtio: console: Un-block reads on chardev close (Amit Shah) [662721 628805]- [virt] virtio: console: Check if portdev is valid in send_control_msg() (Amit Shah) [662721 628805]- [virt] virtio: console: Remove control vq data only if using multiport support (Amit Shah) [662721 628805]- [virt] virtio: console: Reset vdev before removing device (Amit Shah) [662721 628805]- [fs] Fix nfsv4 client lock reclaim behaviour (Sachin Prabhu) [661730 638269]- [scsi] scsi_dh_alua: Handle all states correctly (Mike Snitzer) [659610 636994]- [kernel] execve: improve interactivity and respond to SIGKILL with large arguments (Dave Anderson) [661731 629178]- [virt] xen: handle events as edge-triggered (Andrew Jones) [661737 550724]- [virt] xen: use percpu interrupts for IPIs and VIRQs (Andrew Jones) [661737 550724][2.6.32-71.15.1.el6]- [net] bonding: prevent oopsing on calling pskb_may_pull on shared skb (Andy Gospodarek) [671342 665110]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0283");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0283.html");
script_cve_id("CVE-2010-4165","CVE-2010-4169","CVE-2010-4243");
script_tag(name:"cvss_base", value:"4.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~71.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~71.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~71.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~71.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~71.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~71.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~71.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~71.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

