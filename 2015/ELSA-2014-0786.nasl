# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0786.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123354");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:02:40 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0786");
script_tag(name: "insight", value: "ELSA-2014-0786 -  kernel security, bug fix, and enhancement update - [3.10.0-123.4.2]- Oracle Linux certificates (Alexey Petrenko)[3.10.0-123.4.2]- [fs] aio: fix plug memory disclosure and fix reqs_active accounting backport (Jeff Moyer) [1094604 1094605] {CVE-2014-0206}- [fs] aio: plug memory disclosure and fix reqs_active accounting (Mateusz Guzik) [1094604 1094605] {CVE-2014-0206}[3.10.0-123.4.1]- [kernel] futex: Make lookup_pi_state more robust (Larry Woodman) [1104519 1104520] {CVE-2014-3153}- [kernel] futex: Always cleanup owner tid in unlock_pi (Larry Woodman) [1104519 1104520] {CVE-2014-3153}- [kernel] futex: Validate atomic acquisition in futex_lock_pi_atomic() (Larry Woodman) [1104519 1104520] {CVE-2014-3153}- [kernel] futex: prevent requeue pi on same futex (Larry Woodman) [1104519 1104520] {CVE-2014-3153}- [ethernet] qlcnic: Fix ethtool statistics length calculation (Michal Schmidt) [1104972 1099634]- Revert: [kernel] cputime: Default implementation of nsecs -> cputime conversion (Frederic Weisbecker) [1090974 1047732]- Revert: [kernel] cputime: Bring cputime -> nsecs conversion (Frederic Weisbecker) [1090974 1047732]- Revert: [kernel] cputime: Fix jiffies based cputime assumption on steal accounting (Frederic Weisbecker) [1090974 1047732][3.10.0-123.3.1]- [kernel] mutexes: Give more informative mutex warning in the !lock->owner case (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]- [kernel] mutex: replace CONFIG_HAVE_ARCH_MUTEX_CPU_RELAX with simple ifdef (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]- [kernel] locking/mutexes: Introduce cancelable MCS lock for adaptive spinning (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]- [kernel] locking/mutexes: Modify the way optimistic spinners are queued (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]- [kernel] locking/mutexes: Return false if task need_resched() in mutex_can_spin_on_owner() (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]- [kernel] Restructure the MCS lock defines and locking & Move mcs_spinlock.h into kernel/locking/ (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]- [misc] arch: Introduce smp_load_acquire(), smp_store_release() (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]- [kernel] locking/mutex: Fix debug_mutexes (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]- [kernel] locking/mutex: Fix debug checks (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922]- [kernel] locking/mutexes: Unlock the mutex without the wait_lock (Larry Woodman) [1103629 1087655] [1103630 1087919] [1103631 1087922][3.10.0-123.2.1]- [net] filter: prevent nla extensions to peek beyond the end of the message (Jiri Benc) [1096780 1096781] {CVE-2014-3144 CVE-2014-3145}- [block] floppy: don't write kernel-only members to FDRAWCMD ioctl output (Denys Vlasenko) [1094316 1094318] {CVE-2014-1737 CVE-2014-1738}- [block] floppy: ignore kernel-only members in FDRAWCMD ioctl input (Denys Vlasenko) [1094316 1094318] {CVE-2014-1737 CVE-2014-1738}- [net] core, nfqueue, openvswitch: Orphan frags in skb_zerocopy and handle errors (Jiri Pirko) [1091345 1079014] {CVE-2014-2568}- [net] ipv4: current group_info should be put after using (Jiri Benc) [1087415 1087416] {CVE-2014-2851}- [fs] dcache: make prepend_name() work correctly when called with negative *buflen (Mikulas Patocka) [1099048 1092746]- [fs] dcache: __dentry_path() fixes (Mikulas Patocka) [1099048 1092746]- [fs] dcache: prepend_path() needs to reinitialize dentry/vfsmount/mnt on restarts (Mikulas Patocka) [1099048 1092746]- [target] tcm_fc: Fix use-after-free of ft_tpg (Andy Grover) [1088110 1071340]- [s390] af_iucv: wrong mapping of sent and confirmed skbs (Hendrik Brueckner) [1103064 1098513]- [s390] kernel: avoid page table walk on user space access (Hendrik Brueckner) [1103062 1097687]- [s390] crypto: fix aes, des ctr mode concurrency finding (Hendrik Brueckner) [1103060 1097686]- [net] openvswitch: fix a possible deadlock and lockdep warning (Flavio Leitner) [1103318 1094867]- [mm] filemap: update find_get_pages_tag() to deal with shadow entries (Johannes Weiner) [1103065 1091795]- [mm] page-writeback: fix divide by zero in pos_ratio_polynom (Rik van Riel) [1103067 1091784]- [mm] page-writeback: add strictlimit feature (Rik van Riel) [1103067 1091784]- [fs] xfs: log vector rounding leaks log space (Brian Foster) [1103059 1091136]- [fs] xfs: truncate_setsize should be outside transactions (Brian Foster) [1103059 1091136]- [fs] gfs2: Fix uninitialized VFS inode in gfs2_create_inode (Abhijith Das) [1097407 1087995]- [kernel] futex: Fix pthread_cond_broadcast() to wake up all threads (Larry Woodman) [1103066 1084757]- [net] ip: generate unique IP identificator if local fragmentation is allowed (Jiri Pirko) [1090490 1076106]- [kernel] cputime: Fix jiffies based cputime assumption on steal accounting (Frederic Weisbecker) [1090974 1047732]- [kernel] cputime: Bring cputime -> nsecs conversion (Frederic Weisbecker) [1090974 1047732]- [kernel] cputime: Default implementation of nsecs -> cputime conversion (Frederic Weisbecker) [1090974 1047732]- [x86] irq, pic: Probe for legacy PIC and set legacy_pic appropriately (Vivek Goyal) [1094973 1037957]- [virt] hyperv/vmbus: Negotiate version 3.0 when running on ws2012r2 hosts (Vivek Goyal) [1094973 1037957]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0786");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0786.html");
script_cve_id("CVE-2014-2851","CVE-2014-3153","CVE-2014-1737","CVE-2014-1738","CVE-2014-2568","CVE-2014-3144","CVE-2014-0206","CVE-2014-3145");
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
if(release == "OracleLinux7")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.4.2.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

