# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0911.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123611");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:16 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0911");
script_tag(name: "insight", value: "ELSA-2013-0911 -  kernel security, bug fix, and enhancement update - [2.6.32-358.11.1]- [kernel] perf: fix perf_swevent_enabled array out-of-bound access (Petr Matousek) [962793 962794] {CVE-2013-2094}[2.6.32-358.10.1]- [scsi] be2iscsi : Fix the NOP-In handling code path (Nikola Pajkovsky) [955504 947550]- [scsi] be2iscsi: Fix memory leak in control path of driver (Rob Evers) [955504 947550]- [virt] kvm: validate userspace_addr of memslot (Petr Matousek) [950496 950498] {CVE-2013-1943}- [virt] kvm: fix copy to user with irq disabled (Michael S. Tsirkin) [949985 906602] {CVE-2013-1935}- [net] veth: Dont kfree_skb() after dev_forward_skb() (Jiri Benc) [957712 957713] {CVE-2013-2017}- [net] tcp: Reallocate headroom if it would overflow csum_start (Thomas Graf) [954298 896233]- [net] tcp: take care of misalignments (Thomas Graf) [954298 896233]- [net] skbuff.c cleanup (Thomas Graf) [954298 896233]- [idle] intel_idle: Initialize driver_data correctly in ivb_cstates on IVB processor (Prarit Bhargava) [960864 953630]- [x86] Prevent panic in init_memory_mapping() when booting more than 1TB on AMD systems (Larry Woodman) [962482 869736]- [mm] enforce mmap_min_addr on x86_64 (Rik van Riel) [961431 790921]- [mm] optional next-fit policy for arch_get_unmapped_area (Rik van Riel) [961431 790921]- [mm] fix quadratic behaviour in get_unmapped_area_topdown (Rik van Riel) [961431 790921]- [scsi] Revert: qla2xxx: Optimize existing port name server query matching (Chad Dupuis) [950529 924804]- [scsi] Revert: qla2xxx: Avoid losing any fc ports when loop id's are exhausted (Chad Dupuis) [950529 924804]- [fs] defer do_filp_open() access checks to may_open() (Eric Sandeen) [928683 920752]- [md] dm thin: bump the target version numbers (Mike Snitzer) [924823 922931]- [md] dm-thin: fix discard corruption (Mike Snitzer) [924823 922931]- [md] persistent-data: rename node to btree_node (Mike Snitzer) [924823 922931]- [md] dm: fix limits initialization when there are no data devices (Mike Snitzer) [923096 908851][2.6.32-358.9.1]- [fs] nfs: Fix handling of revoked delegations by setattr (Steve Dickson) [960415 952329]- [fs] nfs: Return the delegation if the server returns NFS4ERR_OPENMODE (Steve Dickson) [960415 952329]- [fs] nfs: Fix another potential state manager deadlock (Steve Dickson) [960436 950598]- [fs] nfs: Fix another open/open_recovery deadlock (Steve Dickson) [960433 916806]- [fs] nfs: Hold reference to layout hdr in layoutget (Steve Dickson) [960429 916726]- [fs] nfs: add 'pnfs_' prefix to get_layout_hdr() and put_layout_hdr() (Steve Dickson) [960429 916726]- [fs] nfs: nfs4_open_done first must check that GETATTR decoded a file type (Steve Dickson) [960412 916722]- [net] sunrpc: Dont start the retransmission timer when out of socket space (Steve Dickson) [960426 916735]- [fs] nfs: Dont use SetPageError in the NFS writeback code (Steve Dickson) [960420 912867]- [fs] nfs: Dont decode skipped layoutgets (Steve Dickson) [927294 904025]- [fs] nfs: nfs4_proc_layoutget returns void (Steve Dickson) [927294 904025]- [fs] nfs: defer release of pages in layoutget (Steve Dickson) [927294 904025]- [fs] nfs: Use kcalloc() when allocating arrays (Steve Dickson) [927294 904025]- [fs] nfs: Fix an ABBA locking issue with session and state serialisation (Steve Dickson) [960417 912842]- [fs] nfs: Fix a race in the pNFS return-on-close code (Steve Dickson) [960417 912842]- [fs] nfs: Do not accept delegated opens when a delegation recall is in effect (Steve Dickson) [960417 912842]- [fs] nfs: Fix a reboot recovery race when opening a file (Steve Dickson) [952613 908524]- [fs] nfs: Ensure delegation recall and byte range lock removal don't conflict (Steve Dickson) [952613 908524]- [fs] nfs: Fix up the return values of nfs4_open_delegation_recall (Steve Dickson) [952613 908524]- [fs] nfs: Dont lose locks when a server reboots during delegation return (Steve Dickson) [952613 908524]- [fs] nfs: Move nfs4_wait_clnt_recover and nfs4_client_recover_expired_lease (Steve Dickson) [952613 908524]- [fs] nfs: Add NFSDBG_STATE (Steve Dickson) [952613 908524]- [fs] nfs: nfs_inode_return_delegation() should always flush dirty data (Steve Dickson) [952613 908524]- [fs] nfs: nfs_client_return_marked_delegations cant flush data (Steve Dickson) [952613 908524]- [fs] nfs: Prevent deadlocks between state recovery and file locking (Steve Dickson) [952613 908524]- [fs] nfs: Allow the state manager to mark an open_owner as being recovered (Steve Dickson) [952613 908524]- [kernel] seqlock: Dont smp_rmb in seqlock reader spin loop (Steve Dickson) [952613 908524]- [kernel] seqlock: add 'raw_seqcount_begin()' function (Steve Dickson) [952613 908524]- [kernel] seqlock: optimise seqlock (Steve Dickson) [952613 908524]- [fs] nfs: don't allow nfs_find_actor to match inodes of the wrong type (Jeff Layton) [921964 913660]- [net] sunrpc: Add barriers to ensure read ordering in rpc_wake_up_task_queue_locked (Dave Wysochanski) [956979 840860][2.6.32-358.8.1]- [fs] raw: don't call set_blocksize when not changing the blocksize (Jeff Moyer) [951406 909482]- [x86] Allow greater than 1TB of RAM on AMD x86_64 sytems (Larry Woodman) [952570 876275]- [netdrv] ixgbe: Only set gso_type to SKB_GSO_TCPV4 as RSC does not support IPv6 (Michael S. Tsirkin) [927292 908196]- [netdrv] bnx2x: set gso_type (Michael S. Tsirkin) [927292 908196]- [netdrv] qlcnic: set gso_type (Michael S. Tsirkin) [927292 908196]- [netdrv] ixgbe: fix gso type (Michael S. Tsirkin) [927292 908196]- [fs] gfs2: Allocate reservation structure before rename and link (Robert S Peterson) [924847 922999][2.6.32-358.7.1]- [infiniband] ipoib: Add missing locking when CM object is deleted (Doug Ledford) [928817 913645]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0911");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0911.html");
script_cve_id("CVE-2013-1935","CVE-2013-1943","CVE-2013-2017");
script_tag(name:"cvss_base", value:"7.8");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.11.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

