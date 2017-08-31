# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1167.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123317");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:02:11 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1167");
script_tag(name: "insight", value: "ELSA-2014-1167 -  kernel security and bug fix update - [2.6.32-431.29.2]- [kernel] futex: Fix errors in nested key ref-counting (Denys Vlasenko) [1094457 1094458] {CVE-2014-0205}- [net] vxlan: fix NULL pointer dereference (Jiri Benc) [1114549 1096351] {CVE-2014-3535}[2.6.32-431.29.1]- [mm] hugetlb: ensure hugepage access is denied if hugepages are not supported (Gustavo Duarte) [1118782 1086450]- [security] keys: Increase root_maxkeys and root_maxbytes sizes (Steve Dickson) [1115542 1113607]- [fs] lockd: Ensure that nlmclnt_block resets block->b_status after a server reboot (Steve Dickson) [1110180 959006]- [net] filter: add vlan tag access (Jiri Benc) [1108526 1082097]- [net] filter: add XOR operation (Jiri Benc) [1108526 1082097]- [net] filter: add SKF_AD_RXHASH and SKF_AD_CPU (Jiri Benc) [1108526 1082097]- [net] filter: Socket filter ancilliary data access for skb->dev->type (Jiri Benc) [1108526 1082097]- [net] filter: Add SKF_AD_QUEUE instruction (Jiri Benc) [1108526 1082097]- [net] filter: ingress socket filter by mark (Jiri Benc) [1108526 1082097]- [netdrv] bonding: look for bridge IPs in arp monitoring (Veaceslav Falico) [1102794 704190]- [s390] af_iucv: wrong mapping of sent and confirmed skbs (Hendrik Brueckner) [1112390 1102248]- [s390] af_iucv: recvmsg problem for SOCK_STREAM sockets (Hendrik Brueckner) [1112390 1102248]- [s390] af_iucv: fix recvmsg by replacing skb_pull() function (Hendrik Brueckner) [1112390 1102248]- [s390] kernel: avoid page table walk on user space access (Hendrik Brueckner) [1111194 1099146]- [s390] qeth: postpone freeing of qdio memory (Hendrik Brueckner) [1112134 1094379]- [s390] qeth: Fix retry logic in hardsetup (Hendrik Brueckner) [1112134 1094379]- [s390] qeth: Recognize return codes of ccw_device_set_online (Hendrik Brueckner) [1112134 1094379]- [s390] qdio: remove API wrappers (Hendrik Brueckner) [1112134 1094379]- [scsi] Ensure medium access timeout counter resets (David Jeffery) [1117153 1036884]- [scsi] Fix error handling when no ULD is attached (David Jeffery) [1117153 1036884]- [scsi] Handle disk devices which can not process medium access commands (David Jeffery) [1117153 1036884]- [fs] nfs: Fix calls to drop_nlink() (Steve Dickson) [1099607 1093819]- [mm] swap: do not skip lowest_bit in scan_swap_map() scan loop (Rafael Aquini) [1099728 1060886]- [mm] swap: fix shmem swapping when more than 8 areas (Rafael Aquini) [1099728 1060886]- [mm] swap: fix swapon size off-by-one (Rafael Aquini) [1099728 1060886]- [md] avoid deadlock when dirty buffers during md_stop (Jes Sorensen) [1121541 994724]- [x86] hyperv: bypass the timer_irq_works() check (Jason Wang) [1112226 1040349][2.6.32-431.28.1]- [kernel] auditsc: audit_krule mask accesses need bounds checking (Denys Vlasenko) [1102704 1102705] {CVE-2014-3917}- [net] ipv4: fix route cache rebuilds (Jiri Pirko) [1113824 1111631]- [fs] nfsd: notify_change needs elevated write count (Mateusz Guzik) [1110177 1105057]- [fs] nfsv4: close needs to handle NFS4ERR_ADMIN_REVOKED (Dave Wysochanski) [1096397 1082127]- [fs] pipe: skip file_update_time on frozen fs (Eric Sandeen) [1114405 1093077]- [fs] nfs: Fail the truncate() if the lock/open stateid is invalid (Steve Dickson) [1090613 1075123]- [fs] nfs: Servers should only check SETATTR stateid open mode on size change (Steve Dickson) [1090613 1075123]- [fs] nfs: Fail data server I/O if stateid represents a lost lock (Steve Dickson) [1090613 1075123]- [fs] nfs: Fix the return value of nfs4_select_rw_stateid (Steve Dickson) [1090613 1075123]- [fs] nfs: Use the open stateid if the delegation has the wrong mode (Steve Dickson) [1090613 1075123]- [fs] nfs: nfs4_stateid_is_current should return 'true' for an invalid stateid (Steve Dickson) [1090613 1075123]- [fs] nfs: fix error return in nfs4_select_rw_stateid (Steve Dickson) [1090613 1075123]- [fs] nfs: Document the recover_lost_locks kernel parameter (Jeff Layton) [1089359 963785]- [fs] nfs: Don't try to recover NFSv4 locks when they are lost (Jeff Layton) [1089359 963785]- [fs] nfs: Fix handling of partially delegated locks (Jeff Layton) [1120074 959788]- [fs] nfs: Convert the nfs4_lock_state->ls_flags to a bit field (Jeff Layton) [1120074 959788]- [x86] Optimize switch_mm() for multi-threaded workloads (Rik van Riel) [1115821 991518]- [netdrv] pppol2tp: fail when socket option level is not SOL_PPPOL2TP [1119461 1119462] {CVE-2014-4943}- [kernel] utrace: force IRET path after utrace_finish_vfork() (Oleg Nesterov) [1115932 1115933] {CVE-2014-4699}[2.6.32-431.27.1]- [scsi] fix performance regression due to inverted blk_get_queue return (Mike Snitzer) [1117582 1098658]- [net] openvswitch: fix use-after-free bug in netns (Flavio Leitner) [1120651 1100127][2.6.32-431.26.1]- [net] gro: fix deliver of trunk packets to VLAN interfaces (Marcelo Ricardo Leitner) [1116231 1112324][2.6.32-431.25.1]- [net] sctp: Fix sk_ack_backlog wrap-around problem (Daniel Borkmann) [1113969 1085932] {CVE-2014-4667}[2.6.32-431.24.1]- [alsa] aloop: Close races at restarting the stream (Jaroslav Kysela) [1112492 1078592]- [alsa] aloop: Export snd_pcm_constraint_mask64() (Jaroslav Kysela) [1112492 1078592]- [alsa] pcm: Warn when buffer preallocation fails (Jaroslav Kysela) [1112492 1078592]- [alsa] aloop: Add SNDRV_PCM_STATE_PAUSED case in wait_for_avail function (Jaroslav Kysela) [1112492 1078592]- [alsa] jack: Unregister input device at disconnection (Jaroslav Kysela) [1112492 1078592]- [alsa] aloop: Optimize module name check (Jaroslav Kysela) [1112492 1078592]- [alsa] pcm: Add fallthru comments (Jaroslav Kysela) [1112492 1078592]- [alsa] aloop: Fix Oops while PM resume (Jaroslav Kysela) [1112492 1078592]- [alsa] aloop: add locking to timer access (Jaroslav Kysela) [1112492 1078592]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1167");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1167.html");
script_cve_id("CVE-2014-4667","CVE-2014-3917","CVE-2014-0205","CVE-2014-3535");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.29.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.29.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.29.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.29.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.29.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.29.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.29.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.29.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.29.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.29.2.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

