# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2016-0715.nasl 6552 2017-07-06 11:49:41Z cfischer $
 
# Authors: 
# Eero Volotinen <eero.volotinen@solinor.fi> 
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://solinor.fi
#
# OpenVAS and security consultance available from openvas@solinor.com
# see https://solinor.fi/openvas-en/ for more information
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
script_oid("1.3.6.1.4.1.25623.1.0.122929");
script_version("$Revision: 6552 $");
script_tag(name:"creation_date", value:"2016-05-09 14:24:46 +0300 (Mon, 09 May 2016)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:49:41 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2016-0715");
script_tag(name: "insight", value: "ELSA-2016-0715 -  kernel security, bug fix, and enhancement update - [2.6.32-573.26.1]- [kernel] revert 'sched: core: Use hrtimer_start_expires' (Jiri Olsa) [1326043 1324318]- [kernel] Revert 'Cleanup bandwidth timers' (Jiri Olsa) [1326043 1324318]- [kernel] revert 'fair: Test list head instead of list entry in throttle_cfs_rq' (Jiri Olsa) [1326043 1324318]- [kernel] revert 'sched, perf: Fix periodic timers' (Jiri Olsa) [1326043 1324318]- [kernel] Revert 'fix KABI break' (Jiri Olsa) [1326043 1324318][2.6.32-573.25.1]- [x86] nmi/64: Fix a paravirt stack-clobbering bug in the NMI code (Denys Vlasenko) [1259580 1259581] {CVE-2015-5157}- [x86] nmi/64: Switch stacks on userspace NMI entry (Denys Vlasenko) [1259580 1259581] {CVE-2015-5157}- [fs] anon_inodes implement dname (Aristeu Rozanski) [1322707 1296019]- [fs] xfs: Avoid pathological backwards allocation (Bill O'Donnell) [1320031 1302777]- [net] sctp: Prevent soft lockup when sctp_accept() is called during a timeout event (Jacob Tanenbaum) [1297421 1297422] {CVE-2015-8767}- [net] udp: move logic out of udp[46]_ufo_send_check (Sabrina Dubroca) [1319276 1299975]- [net] af_unix: Guard against other == sk in unix_dgram_sendmsg (Jakub Sitnicki) [1315696 1309241]- [md] raid10: don't clear bitmap bit when bad-block-list write fails (Jes Sorensen) [1320863 1273546]- [md] raid1: don't clear bitmap bit when bad-block-list write fails (Jes Sorensen) [1320863 1273546]- [md] raid10: submit_bio_wait returns 0 on success (Jes Sorensen) [1320863 1273546]- [md] raid1: submit_bio_wait() returns 0 on success (Jes Sorensen) [1320863 1273546]- [md] crash in md-raid1 and md-raid10 due to incorrect list manipulation (Jes Sorensen) [1320863 1273546]- [md] raid10: ensure device failure recorded before write request returns (Jes Sorensen) [1320863 1273546]- [md] raid1: ensure device failure recorded before write request returns (Jes Sorensen) [1320863 1273546][2.6.32-573.24.1]- [sched] fix KABI break (Seth Jennings) [1314878 1230310]- [sched] fair: Test list head instead of list entry in throttle_cfs_rq (Seth Jennings) [1314878 1230310]- [sched] sched,perf: Fix periodic timers (Seth Jennings) [1314878 1230310]- [sched] sched: debug: Remove the cfs bandwidth timer_active printout (Seth Jennings) [1314878 1230310]- [sched] Cleanup bandwidth timers (Seth Jennings) [1314878 1230310]- [sched] sched: core: Use hrtimer_start_expires (Seth Jennings) [1314878 1230310]- [sched] fair: Fix unlocked reads of some cfs_b->quota/period (Seth Jennings) [1314878 1230310]- [sched] Fix potential near-infinite distribute_cfs_runtime loop (Seth Jennings) [1314878 1230310]- [sched] fair: Fix tg_set_cfs_bandwidth deadlock on rq->lock (Seth Jennings) [1314878 1230310]- [sched] Fix hrtimer_cancel/rq->lock deadlock (Seth Jennings) [1314878 1230310]- [sched] Fix cfs_bandwidth misuse of hrtimer_expires_remaining (Seth Jennings) [1314878 1230310]- [sched] Refine the code in unthrottle_cfs_rq (Seth Jennings) [1314878 1230310]- [sched] Update rq clock earlier in unthrottle_cfs_rq (Seth Jennings) [1314878 1230310]- [block] Fix q_suspended logic error for io submission (David Milburn) [1314209 1227342]- [block] nvme: No lock while DMA mapping data (David Milburn) [1314209 1227342]- [netdrv] ixgbe: finish ixgbe: Update ixgbe to use new vlan accleration (John Greene) [1315706 1249244][2.6.32-573.23.1]- [x86] perf: Add more Broadwell model numbers (Jiri Olsa) [1320035 1242694]- [perf] perf/x86/intel: Remove incorrect model number from Haswell perf (Jiri Olsa) [1320035 1242694]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2016-0715");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2016-0715.html");
script_cve_id("CVE-2015-5157","CVE-2015-8767");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~573.26.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~573.26.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~573.26.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~573.26.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~573.26.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~573.26.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~573.26.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~573.26.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~573.26.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~573.26.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

