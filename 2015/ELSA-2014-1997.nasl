# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-1997.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123219");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:00:52 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-1997");
script_tag(name: "insight", value: "ELSA-2014-1997 -  kernel security and bug fix update - [2.6.32-504.3.3]- [x86] traps: stop using IST for #SS (Petr Matousek) [1172810 1172811] {CVE-2014-9322}[2.6.32-504.3.2]- [md] dm-thin: fix pool_io_hints to avoid looking at max_hw_sectors (Mike Snitzer) [1161420 1161421 1142773 1145230][2.6.32-504.3.1]- [s390] zcrypt: toleration of new crypto adapter hardware (Hendrik Brueckner) [1158311 1134984]- [s390] zcrypt: support for extended number of ap domains (Hendrik Brueckner) [1158311 1134984]- [md] dm-thin: fix potential for infinite loop in pool_io_hints (Mike Snitzer) [1161420 1161421 1142773 1145230][2.6.32-504.2.1]- [fs] udf: Avoid infinite loop when processing indirect ICBs (Jacob Tanenbaum) [1142319 1142320] {CVE-2014-6410}- [fs] isofs: unbound recursion when processing relocated directories (Jacob Tanenbaum) [1142268 1142269] {CVE-2014-5472 CVE-2014-5471}- [net] ipv6: delete expired route in ip6_pmtu_deliver (Hannes Frederic Sowa) [1161418 1156137]- [net] sctp: fix remote memory pressure from excessive queueing (Daniel Borkmann) [1155746 1154676] {CVE-2014-3688}- [net] sctp: fix panic on duplicate ASCONF chunks (Daniel Borkmann) [1155733 1154676] {CVE-2014-3687}- [net] sctp: fix skb_over_panic when receiving malformed ASCONF chunks (Daniel Borkmann) [1147857 1154676] {CVE-2014-3673}- [net] sctp: handle association restarts when the socket is closed (Daniel Borkmann) [1147857 1154676]- [md] dm-thin: refactor requeue_io to eliminate spinlock bouncing (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: optimize retry_bios_on_resume (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: sort the deferred cells (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: direct dispatch when breaking sharing (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: remap the bios in a cell immediately (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: defer whole cells rather than individual bios (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: factor out remap_and_issue_overwrite (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: performance improvement to discard processing (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: grab a virtual cell before looking up the mapping (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: implement thin_merge (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm: improve documentation and code clarity in dm_merge_bvec (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: adjust max_sectors_kb based on thinp blocksize (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] block: fix alignment_offset math that assumes io_min is a power-of-2 (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: throttle incoming IO (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: prefetch missing metadata pages (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-transaction-manager: add support for prefetching blocks of metadata (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin-metadata: change dm_thin_find_block to allow blocking, but not issuing, IO (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-bio-prison: switch to using a red black tree (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-bufio: evict buffers that are past the max age but retain some buffers (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-bufio: switch from a huge hash table to an rbtree (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-bufio: update last_accessed when relinking a buffer (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-bufio: use kzalloc when allocating dm_bufio_client (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin-metadata: do not allow the data block size to change (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: cleanup noflush_work to use a proper completion (Mike Snitzer) [1161420 1161421 1142773 1145230]- [md] dm-thin: fix DMERR typo in pool_status error path (Mike Snitzer) [1161420 1161421 1142773 1145230]- [fs] xfs: xlog_cil_force_lsn doesn't always wait correctly (Eric Sandeen) [1158325 1133304]- [netdrv] ixgbe: allow TXDCTL.WRTHRESH to be 1 will small ITR values (John Greene) [1158326 1132267]- [netdrv] ixgbe: Intel Change to allow itr changes without CONFIG_BQL support (John Greene) [1158326 1132267]- [video] offb: Fix setting of the pseudo-palette for >8bpp (Gerd Hoffmann) [1158328 1142450]- [video] offb: Add palette hack for qemu 'standard vga' framebuffer (Gerd Hoffmann) [1158328 1142450]- [video] offb: Fix bug in calculating requested vram size (Gerd Hoffmann) [1158328 1142450]- [net] sock_queue_err_skb() dont mess with sk_forward_alloc (Jiri Benc) [1155427 1148257]- [net] guard tcp_set_keepalive() to tcp sockets (Florian Westphal) [1141744 1141746] {CVE-2012-6657}- Revert: [net] revert 'bridge: Set vlan_features to allow offloads on vlans' (Vlad Yasevich) [1144442 1121991]- [x86] kvm: fix PIT timer race condition (mguzik) [1149592 1149593] {CVE-2014-3611}- [x86] kvm: vmx: handle invept and invvpid vm exits gracefull (mguzik) [1144826 1144837 1144827 1144838] {CVE-2014-3646 CVE-2014-3645}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-1997");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-1997.html");
script_cve_id("CVE-2014-3687","CVE-2014-3673","CVE-2014-3688","CVE-2014-6410","CVE-2012-6657","CVE-2014-5471","CVE-2014-5472","CVE-2014-9322");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.3.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.3.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.3.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.3.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.3.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.3.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.3.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.3.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.3.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.3.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

