# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0475.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123416");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:03:30 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0475");
script_tag(name: "insight", value: "ELSA-2014-0475 -  kernel security and bug fix update - [2.6.32-431.17.1]- [scsi] qla2xxx: Fixup looking for a space in the outstanding_cmds array in qla2x00_alloc_iocbs() (Chad Dupuis) [1085660 1070856]- [scsi] isci: fix reset timeout handling (David Milburn) [1080600 1040393]- [scsi] isci: correct erroneous for_each_isci_host macro (David Milburn) [1074855 1059325]- [kernel] sched: Fix small race where child->se.parent, cfs_rq might point to invalid ones (Naoya Horiguchi) [1081907 1032350]- [kernel] sched: suppress RCU lockdep splat in task_fork_fair (Naoya Horiguchi) [1081907 1032350]- [kernel] sched: add local variable to store task_group() to avoid kernel stall (Naoya Horiguchi) [1081908 1043733]- [fs] cifs: mask off top byte in get_rfc1002_length() (Sachin Prabhu) [1085358 1069737]- [kernel] Prevent deadlock when post_schedule_rt() results in calling wakeup_kswapd() on multiple CPUs (Larry Woodman) [1086095 1009626]- [scsi] AACRAID Driver compat IOCTL missing capability check (Jacob Tanenbaum) [1033533 1033534] {CVE-2013-6383}- [md] dm-thin: fix rcu_read_lock being held in code that can sleep (Mike Snitzer) [1086007 1060381]- [md] dm-thin: irqsave must always be used with the pool->lock spinlock (Mike Snitzer) [1086007 1060381]- [md] dm-thin: sort the per thin deferred bios using an rb_tree (Mike Snitzer) [1086007 1060381]- [md] dm-thin: use per thin device deferred bio lists (Mike Snitzer) [1086007 1060381]- [md] dm-thin: simplify pool_is_congested (Mike Snitzer) [1086007 1060381]- [md] dm-thin: fix dangling bio in process_deferred_bios error path (Mike Snitzer) [1086007 1060381]- [md] dm-thin: take care to copy the space map root before locking the superblock (Mike Snitzer) [1086007 1060381]- [md] dm-transaction-manager: fix corruption due to non-atomic transaction commit (Mike Snitzer) [1086007 1060381]- [md] dm-space-map-metadata: fix refcount decrement below 0 which caused corruption (Mike Snitzer) [1086007 1060381]- [md] dm-thin: fix Documentation for held metadata root feature (Mike Snitzer) [1086007 1060381]- [md] dm-thin: fix noflush suspend IO queueing (Mike Snitzer) [1086007 1060381]- [md] dm-thin: fix deadlock in __requeue_bio_list (Mike Snitzer) [1086007 1060381]- [md] dm-thin: fix out of data space handling (Mike Snitzer) [1086007 1060381]- [md] dm-thin: ensure user takes action to validate data and metadata consistency (Mike Snitzer) [1086007 1060381]- [md] dm-thin: synchronize the pool mode during suspend (Mike Snitzer) [1086007 1060381]- [md] fix Kconfig indentation (Mike Snitzer) [1086007 1060381]- [md] dm-thin: allow metadata space larger than supported to go unused (Mike Snitzer) [1086007 1060381]- [md] dm-thin: fix the error path for the thin device constructor (Mike Snitzer) [1086007 1060381]- [md] dm-thin: avoid metadata commit if a pool's thin devices haven't changed (Mike Snitzer) [1086007 1060381]- [md] dm-space-map-metadata: fix bug in resizing of thin metadata (Mike Snitzer) [1086007 1060381]- [md] dm-thin: fix pool feature parsing (Mike Snitzer) [1086007 1060381]- [md] dm-space-map-metadata: fix extending the space map (Mike Snitzer) [1086007 1060381]- [md] dm-space-map-common: make sure new space is used during extend (Mike Snitzer) [1086007 1060381]- [md] dm-thin: fix set_pool_mode exposed pool operation races (Mike Snitzer) [1086007 1060381]- [md] dm-thin: eliminate the no_free_space flag (Mike Snitzer) [1086007 1060381]- [md] dm-thin: add error_if_no_space feature (Mike Snitzer) [1086007 1060381]- [md] dm-thin: requeue bios to DM core if no_free_space and in read-only mode (Mike Snitzer) [1086007 1060381]- [md] dm-thin: cleanup and improve no space handling (Mike Snitzer) [1086007 1060381]- [md] dm-thin: log info when growing the data or metadata device (Mike Snitzer) [1086007 1060381]- [md] dm-thin: handle metadata failures more consistently (Mike Snitzer) [1086007 1060381]- [md] dm-thin: factor out check_low_water_mark and use bools (Mike Snitzer) [1086007 1060381]- [md] dm-thin: add mappings to end of prepared_* lists (Mike Snitzer) [1086007 1060381]- [md] dm-thin: return error from alloc_data_block if pool is not in write mode (Mike Snitzer) [1086007 1060381]- [md] dm-thin: use bool rather than unsigned for flags in structures (Mike Snitzer) [1086007 1060381]- [md] dm-persistent-data: cleanup dm-thin specific references in text (Mike Snitzer) [1086007 1060381]- [md] dm-space-map-metadata: limit errors in sm_metadata_new_block (Mike Snitzer) [1086007 1060381]- [md] dm-thin: fix discard support to a previously shared block (Mike Snitzer) [1086007 1060381]- [md] dm-thin: initialize dm_thin_new_mapping returned by get_next_mapping (Mike Snitzer) [1086007 1060381]- [md] dm-space-map: disallow decrementing a reference count below zero (Mike Snitzer) [1086007 1060381]- [md] dm-thin: allow pool in read-only mode to transition to read-write mode (Mike Snitzer) [1086007 1060381]- [md] dm-thin: re-establish read-only state when switching to fail mode (Mike Snitzer) [1086007 1060381]- [md] dm-thin: always fallback the pool mode if commit fails (Mike Snitzer) [1086007 1060381]- [md] dm-thin: switch to read-only mode if metadata space is exhausted (Mike Snitzer) [1086007 1060381]- [md] dm-thin: switch to read only mode if a mapping insert fails (Mike Snitzer) [1086007 1060381]- [md] dm-space-map-metadata: return on failure in sm_metadata_new_block (Mike Snitzer) [1086007 1060381]- [md] dm-space-map-disk: optimise sm_disk_dec_block (Mike Snitzer) [1086007 1060381]- [md] dm-table: print error on preresume failure (Mike Snitzer) [1086007 1060381]- [md] dm-thin: do not expose non-zero discard limits if discards disabled (Mike Snitzer) [1086007 1060381]- [md] dm-thin: always return -ENOSPC if no_free_space is set (Mike Snitzer) [1086007 1060381]- [md] dm-thin: set pool read-only if breaking_sharing fails block allocation (Mike Snitzer) [1086007 1060381]- [md] dm-thin: prefix pool error messages with pool device name (Mike Snitzer) [1086007 1060381]- [md] dm-space-map: optimise sm_ll_dec and sm_ll_inc (Mike Snitzer) [1086007 1060381]- [md] dm-btree: prefetch child nodes when walking tree for a dm_btree_del (Mike Snitzer) [1086007 1060381]- [md] dm-btree: use pop_frame in dm_btree_del to cleanup code (Mike Snitzer) [1086007 1060381]- [md] dm-thin: fix stacking of geometry limits (Mike Snitzer) [1086007 1060381]- [md] dm-thin: add data block size limits to Documentation (Mike Snitzer) [1086007 1060381]- [md] dm-thin: fix metadata dev resize detection (Mike Snitzer) [1086007 1060381]- [md] dm-thin: generate event when metadata threshold passed (Mike Snitzer) [1086007 1060381]- [md] dm-persistent-metadata: add space map threshold callback (Mike Snitzer) [1086007 1060381]- [md] dm-persistent-data: add threshold callback to space map (Mike Snitzer) [1086007 1060381]- [md] dm-thin: detect metadata device resizing (Mike Snitzer) [1086007 1060381]- [md] dm-persistent-data: support space map resizing (Mike Snitzer) [1086007 1060381]- [md] dm-thin: refactor data dev resize (Mike Snitzer) [1086007 1060381]- [md] dm-bufio: initialize read-only module parameters (Mike Snitzer) [1086007 1060381]- [md] dm-bufio: submit writes outside lock (Mike Snitzer) [1086007 1060381]- [md] dm-bufio: add recursive IO request BUG_ON (Mike Snitzer) [1086007 1060381]- [md] dm-bufio: prefetch (Mike Snitzer) [1086007 1060381]- [md] dm-bufio: fix slow IO latency issue specific to RHEL6 (Mike Snitzer) [1086490 1058528]- [netdrv] mlx4_en: Fixed crash when port type is changed (Amir Vadai) [1085658 1059586]- [netdrv] vmxnet3: fix netpoll race condition (Neil Horman) [1083175 1073218]- [net] netfilter: nf_conntrack_dccp: fix skb_header_pointer API usages (Jiri Pirko) [1077345 1077346] {CVE-2014-2523}- [scsi] megaraid_sas: fix a small problem when reading state value from hw (Tomas Henzl) [1078641 1065187]- [fs] gfs2: Increase the max number of ACLs (Robert S Peterson) [1078874 1075713]- [net] filter: let bpf_tell_extensions return SKF_AD_MAX (Daniel Borkmann) [1079872 960275]- [net] introduce SO_BPF_EXTENSIONS (Daniel Borkmann) [1079872 960275]- [scsi] scsi_dh: cosmetic change to sizeof() (Ewan Milne) [1075554 1062494]- [acpi] thermal: Check for thermal zone requirement (Nigel Croxon) [1075651 1021044]- [acpi] thermal: Don't invalidate thermal zone if critical trip point is bad (Nigel Croxon) [1075651 1021044]- [mm] flush pages from pagevec of offlined CPU (Naoya Horiguchi) [1078007 1037467]- [fs] xfs: deprecate nodelaylog option (Eric Sandeen) [1076056 1055644]- [fs] Fix mountpoint reference leakage in linkat (Jeff Layton) [1069848 1059943]- [net] sock: Fix release_cb kABI brekage (Thomas Graf) [1066535 1039723]- [vhost] fix total length when packets are too short (Michael S. Tsirkin) [1064442 1064444] {CVE-2014-0077}- [net] sctp: fix sctp_sf_do_5_1D_ce to verify if peer is AUTH capable (Daniel Borkmann) [1070715 1067451] {CVE-2014-0101}- [vhost] validate vhost_get_vq_desc return value (Michael S. Tsirkin) [1062579 1058677] {CVE-2014-0055}[2.6.32-431.16.1]- [scsi] vmw_pvscsi: Fix pvscsi_abort() function (Ewan Milne) [1077874 1002727][2.6.32-431.15.1]- [kernel] sched: Avoid throttle_cfs_rq() racing with period_timer stopping (Seth Jennings) [1083350 844450][2.6.32-431.14.1]- [net] ip_tunnel: (revert old)/fix ecn decapsulation behaviour (Jiri Pirko) [1078011 1059402]- [net] ipv6: del unreachable route when an addr is deleted on lo (Vivek Dasgupta) [1078798 1028372]- [net] ipv6: add ip6_route_lookup (Vivek Dasgupta) [1078798 1028372]- [net] packet: improve socket create/bind latency in some cases (Daniel Borkmann) [1079870 1045150][2.6.32-431.13.1]- [fs] dcache: fix cleanup on warning in d_splice_alias (J. Bruce Fields) [1063201 1042731]- [net] sctp: fix sctp_connectx abi for ia32 emulation/compat mode (Daniel Borkmann) [1076242 1053547][2.6.32-431.12.1]- [mm] vmscan: re-introduce the ZONE_RECLAIM_NOSCAN bailout for zone_reclaim() (Rafael Aquini) [1073562 1039534]- [mm] vmscan: compaction works against zones, not lruvecs (Johannes Weiner) [1073564 982770]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0475");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0475.html");
script_cve_id("CVE-2014-0077","CVE-2013-6383","CVE-2014-2523");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

