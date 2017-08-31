# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-0864.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123129");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:59:43 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-0864");
script_tag(name: "insight", value: "ELSA-2015-0864 -  kernel security and bug fix update - [2.6.32-504.16.2]- [infiniband] core: Prevent integer overflow in ib_umem_get address arithmetic (Doug Ledford) [1181173 1179327] {CVE-2014-8159}[2.6.32-504.16.1]- [fs] gfs2: Move gfs2_file_splice_write outside of #ifdef (Robert S Peterson) [1198329 1193559]- [security] keys: close race between key lookup and freeing (Radomir Vrbovsky) [1179849 1179850] {CVE-2014-9529}- [net] sctp: fix slab corruption from use after free on INIT collisions (Daniel Borkmann) [1196587 1135425] {CVE-2015-1421}- [fs] gfs2: Allocate reservation during splice_write (Robert S Peterson) [1198329 1193559]- [fs] nfs: Be less aggressive about returning delegations for open files (Steve Dickson) [1196314 1145334]- [fs] nfs: Avoid PUTROOTFH when managing leases (Benjamin Coddington) [1196313 1143013]- [crypto] testmgr: mark rfc4106(gcm(aes)) as fips_allowed (Jarod Wilson) [1194983 1185395]- [crypto] Extending the RFC4106 AES-GCM test vectors (Jarod Wilson) [1194983 1185395]- [char] raw: Return short read or 0 at end of a raw device, not EIO (Jeff Moyer) [1195747 1142314]- [scsi] hpsa: Use local workqueues instead of system workqueues - part1 (Tomas Henzl) [1193639 1134115]- [x86] kvm: vmx: invalid host cr4 handling across vm entries (Jacob Tanenbaum) [1153326 1153327] {CVE-2014-3690}- [fs] isofs: Fix unchecked printing of ER records (Radomir Vrbovsky) [1180481 1180492] {CVE-2014-9584}- [fs] bio: fix argument of __bio_add_page() for max_sectors > 0xffff (Fam Zheng) [1198428 1166763]- [media] ttusb-dec: buffer overflow in ioctl (Alexander Gordeev) [1170971 1167115] {CVE-2014-8884}- [kernel] trace: insufficient syscall number validation in perf and ftrace subsystems (Jacob Tanenbaum) [1161567 1161568] {CVE-2014-7826 CVE-2014-7825}- [fs] nfs: Fix a delegation callback race (Dave Wysochanski) [1187639 1149831]- [fs] nfs: Don't use the delegation->inode in nfs_mark_return_delegation() (Dave Wysochanski) [1187639 1149831]- [infiniband] ipoib: don't queue a work struct up twice (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: make sure we reap all our ah on shutdown (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: cleanup a couple debug messages (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: flush the ipoib_workqueue on unregister (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: fix ipoib_mcast_restart_task (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: fix race between mcast_dev_flush and mcast_join (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: remove unneeded locks (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: don't restart our thread on ENETRESET (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: Handle -ENETRESET properly in our callback (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: make delayed tasks not hold up everything (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: Add a helper to restart the multicast task (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: fix IPOIB_MCAST_RUN flag usage (Doug Ledford) [1187664 1187666 1184072 1159925]- [infiniband] ipoib: Remove unnecessary port query (Doug Ledford) [1187664 1187666 1184072 1159925]- [x86] kvm: Avoid pagefault in kvm_lapic_sync_to_vapic (Paolo Bonzini) [1192055 1116398]- [s390] kernel: fix cpu target address of directed yield (Hendrik Brueckner) [1188339 1180061]- [mm] memcg: do not allow task about to OOM kill to bypass the limit (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [mm] memcg: do not declare OOM from __GFP_NOFAIL allocations (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [fs] buffer: move allocation failure loop into the allocator (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [mm] memcg: handle non-error OOM situations more gracefully (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [mm] memcg: do not trap chargers with full callstack on OOM (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [mm] memcg: rework and document OOM waiting and wakeup (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [mm] memcg: enable memcg OOM killer only for user faults (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [x86] mm: finish user fault error path with fatal signal (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [mm] pass userspace fault flag to generic fault handler (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [s390] mm: do not invoke OOM killer on kernel fault OOM (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [powerpc] mm: remove obsolete init OOM protection (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [powerpc] mm: invoke oom-killer from remaining unconverted page fault handlers (Johannes Weiner) [1198110 1088334] {CVE-2014-8171}- [security] selinux: Permit bounded transitions under NO_NEW_PRIVS or NOSUID (Denys Vlasenko) [1104567 1104568] {CVE-2014-3215}- [security] Add PR__NO_NEW_PRIVS to prevent execve from granting privs (Denys Vlasenko) [1104567 1104568] {CVE-2014-3215}[2.6.32-504.15.1]- [netdrv] ixgbe: remove CIAA/D register reads from bad VF check (John Greene) [1196312 1156061]- [pci] Make FLR and AF FLR reset warning messages different (Myron Stowe) [1192365 1184540]- [pci] Fix unaligned access in AF transaction pending test (Myron Stowe) [1192365 1184540]- [pci] Merge multi-line quoted strings (Myron Stowe) [1192365 1184540]- [pci] Wrong register used to check pending traffic (Myron Stowe) [1192365 1184540]- [pci] Add pci_wait_for_pending() -- refactor pci_wait_for_pending_transaction() (Myron Stowe) [1192365 1184540]- [pci] Use pci_wait_for_pending_transaction() instead of for loop (Myron Stowe) [1192365 1184540]- [pci] Add pci_wait_for_pending_transaction() (Myron Stowe) [1192365 1184540]- [pci] Wait for pending transactions to complete before 82599 FLR (Myron Stowe) [1192365 1184540]- [scsi] storvsc: fix a bug in storvsc limits (Vitaly Kuznetsov) [1196532 1174168][2.6.32-504.14.1]- [s390] crypto: kernel oops at insmod of the z90crypt device driver (Hendrik Brueckner) [1191916 1172137]- [sound] alsa: usb-audio: Fix crash at re-preparing the PCM stream (Jerry Snitselaar) [1192105 1167059]- [usb] ehci: bugfix: urb->hcpriv should not be NULL (Jerry Snitselaar) [1192105 1167059]- [mm] mmap: uncached vma support with writenotify (Jerry Snitselaar) [1192105 1167059]- [kernel] futex: Mention key referencing differences between shared and private futexes (Larry Woodman) [1192107 1167405]- [kernel] futex: Ensure get_futex_key_refs() always implies a barrier (Larry Woodman) [1192107 1167405][2.6.32-504.13.1]- [netdrv] enic: fix rx skb checksum (Stefan Assmann) [1189068 1115505]- [scsi] Revert 'fix our current target reap infrastructure' (David Milburn) [1188941 1168072]- [scsi] Revert 'dual scan thread bug fix' (David Milburn) [1188941 1168072]- [net] tcp: do not copy headers in tcp_collapse() (Alexander Duyck) [1188838 1156289]- [net] tcp: use tcp_flags in tcp_data_queue() (Alexander Duyck) [1188838 1156289]- [net] tcp: use TCP_SKB_CB(skb)->tcp_flags in input path (Alexander Duyck) [1188838 1156289]- [net] tcp: remove unused tcp_fin() parameters (Alexander Duyck) [1188838 1156289]- [net] tcp: rename tcp_skb_cb flags (Alexander Duyck) [1188838 1156289]- [net] tcp: unify tcp flag macros (Alexander Duyck) [1188838 1156289]- [net] tcp: unalias tcp_skb_cb flags and ip_dsfield (Alexander Duyck) [1188838 1156289]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-0864");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-0864.html");
script_cve_id("CVE-2014-3690","CVE-2014-7825","CVE-2014-7826","CVE-2014-8884","CVE-2015-1421","CVE-2014-3215","CVE-2014-8171","CVE-2014-9529","CVE-2014-9584");
script_tag(name:"cvss_base", value:"10.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.16.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.16.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.16.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.16.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.16.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.16.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.16.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.16.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.16.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.16.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

