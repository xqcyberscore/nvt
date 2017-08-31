# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1221.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123082");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 13:59:07 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1221");
script_tag(name: "insight", value: "ELSA-2015-1221 -  kernel security, bug fix, and enhancement update - [2.6.32-504.30.3]- [redhat] spec: Update dracut dependency to pull in drbg module (Frantisek Hrbata) [1241517 1241338][2.6.32-504.30.2]- [crypto] rng: Remove krng (Herbert Xu) [1233512 1226418]- [crypto] drbg: Add stdrng alias and increase priority (Herbert Xu) [1233512 1226418]- [crypto] seqiv: Move IV seeding into init function (Herbert Xu) [1233512 1226418]- [crypto] eseqiv: Move IV seeding into init function (Herbert Xu) [1233512 1226418]- [crypto] chainiv: Move IV seeding into init function (Herbert Xu) [1233512 1226418][2.6.32-504.30.1]- [net] Fix checksum features handling in netif_skb_features() (Vlad Yasevich) [1231690 1220247][2.6.32-504.29.1]- [net] gso: fix skb_segment for non-offset skb pointers (Jiri Benc) [1229586 1200533][2.6.32-504.28.1]- [fs] pipe: fix pipe corruption and iovec overrun on partial copy (Seth Jennings) [1202860 1185166] {CVE-2015-1805}- [net] ipv4: Missing sk_nulls_node_init in ping_unhash (Denys Vlasenko) [1218102 1218103] {CVE-2015-3636}- [net] conntrack: RFC5961 challenge ACK confuse conntrack LAST-ACK transition (Jesper Brouer) [1227467 1227468 1212801 1200541]- [net] tcp: Restore RFC5961-compliant behavior for SYN packets (Jesper Brouer) [1227467 1227468 1212801 1200541]- [x86] kernel: ignore NMI IOCK when in kdump kernel (Jerry Snitselaar) [1225054 1196263]- [x86] asm/entry/64: Remove a bogus 'ret_from_fork' optimization (Mateusz Guzik) [1209232 1209233] {CVE-2015-2830}- [fs] gfs2: try harder to obtain journal lock during recovery (Abhijith Das) [1222588 1110846]for core_pmu (Jiri Olsa) [1219149 1188336]- [x86] mm: Linux stack ASLR implementation (Jacob Tanenbaum) [1195682 1195683] {CVE-2015-1593}- [fs] xfs: DIO write completion size updates race (Brian Foster) [1218499 1198440]- [net] ipv6: Don't reduce hop limit for an interface (Denys Vlasenko) [1208492 1208493]- [net] vlan: more careful checksum features handling (Vlad Yasevich) [1221844 1212384]- [kernel] tracing: Export tracing clock functions (Jerry Snitselaar) [1217986 1212502]- [edac] sb_edac: fix corruption/crash on imbalanced Haswell home agents (Seth Jennings) [1213468 1210148]- [netdrv] tun: Fix csum_start with VLAN acceleration (Jason Wang) [1217189 1036482]- [netdrv] tun: unbreak truncated packet signalling (Jason Wang) [1217189 1036482]- [netdrv] tuntap: hardware vlan tx support (Jason Wang) [1217189 1036482]- [vhost] vhost-net: fix handle_rx buffer size (Jason Wang) [1217189 1036482]- [netdrv] ixgbe: fix X540 Completion timeout (John Greene) [1215855 1150343]- [char] tty: drop driver reference in tty_open fail path (Mateusz Guzik) [1201893 1201894]- [netdrv] macvtap: Fix csum_start when VLAN tags are present (Vlad Yasevich) [1215914 1123697]- [netdrv] macvtap: signal truncated packets (Vlad Yasevich) [1215914 1123697]- [netdrv] macvtap: restore vlan header on user read (Vlad Yasevich) [1215914 1123697]- [netdrv] macvlan: Initialize vlan_features to turn on offload support (Vlad Yasevich) [1215914 1123697]- [netdrv] macvlan: Add support for 'always_on' offload features (Vlad Yasevich) [1215914 1123697]- [netdrv] mactap: Fix checksum errors for non-gso packets in bridge mode (Vlad Yasevich) [1215914 1123697]- [netdrv] revert 'macvlan: fix checksums error when we are in bridge mode' (Vlad Yasevich) [1215914 1123697]- [net] core: Correctly set segment mac_len in skb_segment() (Vlad Yasevich) [1215914 1123697]- [net] core: generalize skb_segment() (Vlad Yasevich) [1215914 1123697]- [net] core: Add skb_headers_offset_update helper function (Vlad Yasevich) [1215914 1123697]- [netdrv] ixgbe: Correctly disable VLAN filter in promiscuous mode (Vlad Yasevich) [1215914 1123697]- [netdrv] ixgbe: remove vlan_filter_disable and enable functions (Vlad Yasevich) [1215914 1123697]- [netdrv] qlge: Fix TSO for non-accelerated vlan traffic (Vlad Yasevich) [1215914 1123697]- [netdrv] i40evf: Fix TSO and hw checksums for non-accelerated vlan packets (Vlad Yasevich) [1215914 1123697]- [netdrv] i40e: Fix TSO and hw checksums for non-accelerated vlan packets (Vlad Yasevich) [1215914 1123697]- [netdrv] ehea: Fix TSO and hw checksums with non-accelerated vlan packets (Vlad Yasevich) [1215914 1123697]- [netdrv] e1000: Fix TSO for non-accelerated vlan traffic (Vlad Yasevich) [1215914 1123697]- [kernel] ipc: sysv shared memory limited to 8TiB (George Beshers) [1224301 1171218]- [mm] hugetlb: improve page-fault scalability (Larry Woodman) [1212300 1120365]- [netdrv] hyperv: Fix the total_data_buflen in send path (Jason Wang) [1222556 1132918]- [crypto] drbg: fix maximum value checks on 32 bit systems (Herbert Xu) [1225950 1219907]- [crypto] drbg: remove configuration of fixed values (Herbert Xu) [1225950 1219907][2.6.32-504.27.1]- [netdrv] mlx4_en: current_mac isn't updated in port up (Amir Vadai) [1224383 1081667]- [netdrv] mlx4_en: Fix mac_hash database inconsistency (Amir Vadai) [1224383 1081667]- [netdrv] mlx4_en: Protect MAC address modification with the state_lock mutex (Amir Vadai) [1224383 1081667]- [netdrv] mlx4_en: Fix errors in MAC address changing when port is down (Amir Vadai) [1224383 1081667]- [netdrv] mlx4: Verify port number in __mlx4_unregister_mac (Amir Vadai) [1224383 1081667]- [netdrv] mlx4_en: Adding missing initialization of perm_addr (Amir Vadai) [1225489 1120930][2.6.32-504.26.1]- [kernel] sched: Fix clock_gettime(CLOCK_[PROCESS/THREAD]_CPUTIME_ID) monotonicity (Seth Jennings) [1219501 1140024]- [kernel] sched: Replace use of entity_key() (Larry Woodman) [1219123 1124603][2.6.32-504.25.1]- [net] ipvs: allow rescheduling of new connections when port reuse is detected (Marcelo Leitner) [1222771 1108514]- [net] ipvs: Fix reuse connection if real server is dead (Marcelo Leitner) [1222771 1108514]- [netdrv] bonding: fix locking in enslave failure path (Nikolay Aleksandrov) [1222483 1221856]- [netdrv] bonding: primary_slave & curr_active_slave are not cleaned on enslave failure (Nikolay Aleksandrov) [1222483 1221856]- [netdrv] bonding: vlans don't get deleted on enslave failure (Nikolay Aleksandrov) [1222483 1221856]- [netdrv] bonding: mc addresses don't get deleted on enslave failure (Nikolay Aleksandrov) [1222483 1221856]- [netdrv] bonding: IFF_BONDING is not stripped on enslave failure (Nikolay Aleksandrov) [1222483 1221856]- [netdrv] bonding: fix error handling if slave is busy v2 (Nikolay Aleksandrov) [1222483 1221856][2.6.32-504.24.1]- [mm] readahead: get back a sensible upper limit (Rafael Aquini) [1215755 1187940]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1221");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1221.html");
script_cve_id("CVE-2015-1593","CVE-2015-2830","CVE-2011-5321","CVE-2015-2922","CVE-2015-3636");
script_tag(name:"cvss_base", value:"5.0");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.30.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.30.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.30.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.30.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.30.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.30.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.30.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.30.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.30.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.30.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

