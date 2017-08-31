# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1081.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123106");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:59:26 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1081");
script_tag(name: "insight", value: "ELSA-2015-1081 -  kernel security, bug fix, and enhancement update - [2.6.32-504.23.4]- [crypto] drbg: fix maximum value checks on 32 bit systems (Herbert Xu) [1225950 1219907]- [crypto] drbg: remove configuration of fixed values (Herbert Xu) [1225950 1219907][2.6.32-504.23.3]- [netdrv] bonding: fix locking in enslave failure path (Nikolay Aleksandrov) [1222483 1221856]- [netdrv] bonding: primary_slave & curr_active_slave are not cleaned on enslave failure (Nikolay Aleksandrov) [1222483 1221856]- [netdrv] bonding: vlans don't get deleted on enslave failure (Nikolay Aleksandrov) [1222483 1221856]- [netdrv] bonding: mc addresses don't get deleted on enslave failure (Nikolay Aleksandrov) [1222483 1221856]- [netdrv] bonding: IFF_BONDING is not stripped on enslave failure (Nikolay Aleksandrov) [1222483 1221856]- [netdrv] bonding: fix error handling if slave is busy v2 (Nikolay Aleksandrov) [1222483 1221856][2.6.32-504.23.2]- [fs] pipe: fix pipe corruption and iovec overrun on partial copy (Seth Jennings) [1202860 1185166] {CVE-2015-1805}[2.6.32-504.23.1]- [x86] crypto: sha256_ssse3 - fix stack corruption with SSSE3 and AVX implementations (Herbert Xu) [1218681 1201490]- [scsi] storvsc: ring buffer failures may result in I/O freeze (Vitaly Kuznetsov) [1215754 1171676]- [scsi] storvsc: get rid of overly verbose warning messages (Vitaly Kuznetsov) [1215753 1167967]- [scsi] storvsc: NULL pointer dereference fix (Vitaly Kuznetsov) [1215753 1167967]- [netdrv] ixgbe: fix detection of SFP+ capable interfaces (John Greene) [1213664 1150343]- [x86] crypto: aesni - fix memory usage in GCM decryption (Kurt Stutsman) [1213329 1213330] {CVE-2015-3331}[2.6.32-504.22.1]- [kernel] hrtimer: Prevent hrtimer_enqueue_reprogram race (Prarit Bhargava) [1211940 1136958]- [kernel] hrtimer: Preserve timer state in remove_hrtimer() (Prarit Bhargava) [1211940 1136958]- [crypto] testmgr: fix RNG return code enforcement (Herbert Xu) [1212695 1208804]- [net] netfilter: xtables: make use of caller family rather than target family (Florian Westphal) [1212057 1210697]- [net] dynticks: avoid flow_cache_flush() interrupting every core (Marcelo Leitner) [1210595 1191559]- [tools] perf: Fix race in build_id_cache__add_s() (Milos Vyletel) [1210593 1204102]- [infiniband] ipath+qib: fix dma settings (Doug Ledford) [1208621 1171803]- [fs] dcache: return -ESTALE not -EBUSY on distributed fs race (J. Bruce Fields) [1207815 1061994]- [net] neigh: Keep neighbour cache entries if number of them is small enough (Jiri Pirko) [1207352 1199856]- [x86] crypto: sha256_ssse3 - also test for BMI2 (Herbert Xu) [1204736 1201560]- [scsi] qla2xxx: fix race in handling rport deletion during recovery causes panic (Chad Dupuis) [1203544 1102902]- [redhat] configs: Enable SSSE3 acceleration by default (Herbert Xu) [1201668 1036216]- [crypto] sha512: Create module providing optimized SHA512 routines using SSSE3, AVX or AVX2 instructions (Herbert Xu) [1201668 1036216]- [crypto] sha512: Optimized SHA512 x86_64 assembly routine using AVX2 RORX instruction (Herbert Xu) [1201668 1036216]- [crypto] sha512: Optimized SHA512 x86_64 assembly routine using AVX instructions (Herbert Xu) [1201668 1036216]- [crypto] sha512: Optimized SHA512 x86_64 assembly routine using Supplemental SSE3 instructions (Herbert Xu) [1201668 1036216]- [crypto] sha512: Expose generic sha512 routine to be callable from other modules (Herbert Xu) [1201668 1036216]- [crypto] sha256: Create module providing optimized SHA256 routines using SSSE3, AVX or AVX2 instructions (Herbert Xu) [1201668 1036216]- [crypto] sha256: Optimized sha256 x86_64 routine using AVX2's RORX instructions (Herbert Xu) [1201668 1036216]- [crypto] sha256: Optimized sha256 x86_64 assembly routine with AVX instructions (Herbert Xu) [1201668 1036216]- [crypto] sha256: Optimized sha256 x86_64 assembly routine using Supplemental SSE3 instructions (Herbert Xu) [1201668 1036216]- [crypto] sha256: Expose SHA256 generic routine to be callable externally (Herbert Xu) [1201668 1036216]- [crypto] rng: RNGs must return 0 in success case (Herbert Xu) [1201669 1199230]- [fs] isofs: infinite loop in CE record entries (Jacob Tanenbaum) [1175243 1175245] {CVE-2014-9420}- [x86] vdso: ASLR bruteforce possible for vdso library (Jacob Tanenbaum) [1184896 1184897] {CVE-2014-9585}- [kernel] time: ntp: Correct TAI offset during leap second (Prarit Bhargava) [1201674 1199134]- [scsi] lpfc: correct device removal deadlock after link bounce (Rob Evers) [1211910 1194793]- [scsi] lpfc: Linux lpfc driver doesn't re-establish the link after a cable pull on LPe12002 (Rob Evers) [1211910 1194793]- [x86] switch_to(): Load TLS descriptors before switching DS and ES (Denys Vlasenko) [1177353 1177354] {CVE-2014-9419}- [net] vlan: Don't propagate flag changes on down interfaces (Jiri Pirko) [1173501 1135347]- [net] bridge: register vlan group for br ports (Jiri Pirko) [1173501 1135347]- [netdrv] tg3: Use new VLAN code (Jiri Pirko) [1173501 1135347]- [netdrv] be2net: move to new vlan model (Jiri Pirko) [1173501 1135347]- [net] vlan: mask vlan prio bits (Jiri Pirko) [1173501 1135347]- [net] vlan: don't deliver frames for unknown vlans to protocols (Jiri Pirko) [1173501 1135347]- [net] vlan: allow nested vlan_do_receive() (Jiri Pirko) [1173501 1135347]- [net] allow vlan traffic to be received under bond (Jiri Pirko) [1173501 1135347]- [net] vlan: goto another_round instead of calling __netif_receive_skb (Jiri Pirko) [1173501 1135347]- [net] bonding: fix bond_arp_rcv setting and arp validate desync state (Jiri Pirko) [1173501 1135347]- [net] bonding: remove packet cloning in recv_probe() (Jiri Pirko) [1173501 1135347]- [net] bonding: Fix LACPDU rx_dropped commit (Jiri Pirko) [1173501 1135347]- [net] bonding: don't increase rx_dropped after processing LACPDUs (Jiri Pirko) [1173501 1135347]- [net] bonding: use local function pointer of bond->recv_probe in bond_handle_frame (Jiri Pirko) [1173501 1135347]- [net] bonding: move processing of recv handlers into handle_frame() (Jiri Pirko) [1173501 1135347]- [netdrv] revert 'bonding: fix bond_arp_rcv setting and arp validate desync state' (Jiri Pirko) [1173501 1135347]- [netdrv] revert 'bonding: check for vlan device in bond_3ad_lacpdu_recv()' (Jiri Pirko) [1173501 1135347]- [net] vlan: Always untag vlan-tagged traffic on input (Jiri Pirko) [1173501 1135347]- [net] Make skb->skb_iif always track skb->dev (Jiri Pirko) [1173501 1135347]- [net] vlan: fix a potential memory leak (Jiri Pirko) [1173501 1135347]- [net] vlan: fix mac_len recomputation in vlan_untag() (Jiri Pirko) [1173501 1135347]- [net] vlan: reset headers on accel emulation path (Jiri Pirko) [1173501 1135347]- [net] vlan: Fix the ingress VLAN_FLAG_REORDER_HDR check (Jiri Pirko) [1173501 1135347]- [net] vlan: make non-hw-accel rx path similar to hw-accel (Jiri Pirko) [1173501 1135347]- [net] allow handlers to be processed for orig_dev (Jiri Pirko) [1173501 1135347]- [net] bonding: get netdev_rx_handler_unregister out of locks (Jiri Pirko) [1173501 1135347]- [net] bonding: fix rx_handler locking (Jiri Pirko) [1173501 1135347]- [net] introduce rx_handler results and logic around that (Jiri Pirko) [1173501 1135347]- [net] bonding: register slave pointer for rx_handler (Jiri Pirko) [1173501 1135347]- [net] bonding: COW before overwriting the destination MAC address (Jiri Pirko) [1173501 1135347]- [net] bonding: convert bonding to use rx_handler (Jiri Pirko) [1173501 1135347]- [net] openvswitch: use rx_handler_data pointer to store vport pointer (Jiri Pirko) [1173501 1135347]- [net] add a synchronize_net() in netdev_rx_handler_unregister() (Jiri Pirko) [1173501 1135347]- [net] add rx_handler data pointer (Jiri Pirko) [1173501 1135347]- [net] replace hooks in __netif_receive_skb (Jiri Pirko) [1173501 1135347]- [net] fix conflict between null_or_orig and null_or_bond (Jiri Pirko) [1173501 1135347]- [net] remove the unnecessary dance around skb_bond_should_drop (Jiri Pirko) [1173501 1135347]- [net] revert 'bonding: fix receiving of dups due vlan hwaccel' (Jiri Pirko) [1173501 1135347]- [net] uninline skb_bond_should_drop() (Jiri Pirko) [1173501 1135347]- [net] bridge: Set vlan_features to allow offloads on vlans (Jiri Pirko) [1173501 1135347]- [net] bridge: convert br_features_recompute() to ndo_fix_features (Jiri Pirko) [1173501 1135347]- [net] revert 'bridge: explictly tag vlan-accelerated frames destined to the host' (Jiri Pirko) [1173501 1135347]- [net] revert 'fix vlan gro path' (Jiri Pirko) [1173501 1135347]- [net] revert 'bridge: do not learn from exact matches' (Jiri Pirko) [1173501 1135347]- [net] revert 'bridge gets duplicate packets when using vlan over bonding' (Jiri Pirko) [1173501 1135347]- [net] llc: remove noisy WARN from llc_mac_hdr_init (Jiri Pirko) [1173501 1135347]- [net] bridge: stp: ensure mac header is set (Jiri Pirko) [1173501 1135347]- [net] vlan: remove reduntant check in ndo_fix_features callback (Jiri Pirko) [1173501 1135347]- [net] vlan: enable soft features regardless of underlying device (Jiri Pirko) [1173501 1135347]- [net] vlan: don't call ndo_vlan_rx_register on hardware that doesn't have vlan support (Jiri Pirko) [1173501 1135347]- [net] vlan: Fix vlan_features propagation (Jiri Pirko) [1173501 1135347]- [net] vlan: convert VLAN devices to use ndo_fix_features() (Jiri Pirko) [1173501 1135347]- [net] revert 'vlan: Avoid broken offload configuration when reorder_hdr is disabled' (Jiri Pirko) [1173501 1135347]- [net] vlan: vlan device is lockless do not transfer real_num__queues (Jiri Pirko) [1173501 1135347]- [net] vlan: consolidate 8021q tagging (Jiri Pirko) [1173501 1135347]- [net] propagate NETIF_F_HIGHDMA to vlans (Jiri Pirko) [1173501 1135347]- [net] Fix a memmove bug in dev_gro_receive() (Jiri Pirko) [1173501 1135347]- [net] vlan: remove check for headroom in vlan_dev_create (Jiri Pirko) [1173501 1135347]- [net] vlan: set hard_header_len when VLAN offload features are toggled (Jiri Pirko) [1173501 1135347]- [net] vlan: Calling vlan_hwaccel_do_receive() is always valid (Jiri Pirko) [1173501 1135347]- [net] vlan: Centralize handling of hardware acceleration (Jiri Pirko) [1173501 1135347]- [net] vlan: finish removing vlan_find_dev from public header (Jiri Pirko) [1173501 1135347]- [net] vlan: make vlan_find_dev private (Jiri Pirko) [1173501 1135347]- [net] vlan: Avoid hash table lookup to find group (Jiri Pirko) [1173501 1135347]- [net] revert 'vlan: Add helper functions to manage vlans on bonds and slaves' (Jiri Pirko) [1173501 1135347]- [net] revert 'bonding: assign slaves their own vlan_groups' (Jiri Pirko) [1173501 1135347]- [net] revert 'bonding: fix regression on vlan module removal' (Jiri Pirko) [1173501 1135347]- [net] revert 'bonding: Always add vid to new slave group' (Jiri Pirko) [1173501 1135347]- [net] revert 'bonding: Fix up refcounting issues with bond/vlan config' (Jiri Pirko) [1173501 1135347]- [net] revert '8021q/vlan: filter device events on bonds' (Jiri Pirko) [1173501 1135347]- [net] vlan: Use vlan_dev_real_dev in vlan_hwaccel_do_receive (Jiri Pirko) [1173501 1135347]- [net] gro: __napi_gro_receive() optimizations (Jiri Pirko) [1173501 1135347]- [net] vlan: Rename VLAN_GROUP_ARRAY_LEN to VLAN_N_VID (Jiri Pirko) [1173501 1135347]- [net] vlan: make vlan_hwaccel_do_receive() return void (Jiri Pirko) [1173501 1135347]- [net] vlan: init_vlan should not copy slave or master flags (Jiri Pirko) [1173501 1135347]- [net] vlan: updates vlan real_num_tx_queues (Jiri Pirko) [1173501 1135347]- [net] vlan: adds vlan_dev_select_queue (Jiri Pirko) [1173501 1135347]- [net] llc: use dev_hard_header (Jiri Pirko) [1173501 1135347]- [net] vlan: support 'loose binding' to the underlying network device (Jiri Pirko) [1173501 1135347]- [net] revert 'net: don't set VLAN_TAG_PRESENT for VLAN 0 frames' (Jiri Pirko) [1173501 1135347]- [net] bridge: Add support for TX vlan offload (Jiri Pirko) [1173562 1146391]- [net] revert 'bridge: Set vlan_features to allow offloads on vlans' (Vlad Yasevich) [1144442 1121991][2.6.32-504.21.1]- [netdrv] ixgbe: Fix memory leak in ixgbe_free_q_vector, missing rcu (John Greene) [1210901 1150343]- [netdrv] ixgbe: Fix tx_packets and tx_bytes stats not updating (John Greene) [1210901 1150343]- [netdrv] qlcnic: Fix update of ethtool stats (Chad Dupuis) [1210902 1148019][2.6.32-504.20.1]- [fs] exec: do not abuse ->cred_guard_mutex in threadgroup_lock() (Petr Oros) [1208620 1169225]- [kernel] cgroup: always lock threadgroup during migration (Petr Oros) [1208620 1169225]- [kernel] threadgroup: extend threadgroup_lock() to cover exit and exec (Petr Oros) [1208620 1169225]- [kernel] threadgroup: rename signal->threadgroup_fork_lock to ->group_rwsem (Petr Oros) [1208620 1169225][2.6.32-504.19.1]- [mm] memcg: fix crash in re-entrant cgroup_clear_css_refs() (Johannes Weiner) [1204626 1168185][2.6.32-504.18.1]- [fs] cifs: Use key_invalidate instead of the rh_key_invalidate() (Sachin Prabhu) [1203366 885899]- [fs] KEYS: Add invalidation support (Sachin Prabhu) [1203366 885899]- [infiniband] core: Prevent integer overflow in ib_umem_get address arithmetic (Doug Ledford) [1181173 1179327] {CVE-2014-8159}[2.6.32-504.17.1]- [x86] fpu: shift clear_used_math() from save_i387_xstate() to handle_signal() (Oleg Nesterov) [1199900 1196262]- [x86] fpu: change save_i387_xstate() to rely on unlazy_fpu() (Oleg Nesterov) [1199900 1196262]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1081");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1081.html");
script_cve_id("CVE-2014-8159","CVE-2015-3331","CVE-2015-1805","CVE-2014-9419","CVE-2014-9420","CVE-2014-9585");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.23.4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.23.4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.23.4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.23.4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.23.4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.23.4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.23.4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.23.4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.23.4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.23.4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

