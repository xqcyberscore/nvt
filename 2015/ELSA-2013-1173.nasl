# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-1173.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123581");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:05:49 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-1173");
script_tag(name: "insight", value: "ELSA-2013-1173 -  kernel security and bug fix update - [2.6.32-358.18.1]- [x86] perf/x86: Fix offcore_rsp valid mask for SNB/IVB (Nikola Pajkovsky) [971314 971315] {CVE-2013-2146}- [net] br: fix schedule while atomic issue in br_features_recompute() (Jiri Pirko) [990464 980876]- [scsi] isci: Fix a race condition in the SSP task management path (David Milburn) [990470 978609]- [bluetooth] L2CAP - Fix info leak via getsockname() (Jacob Tanenbaum) [922417 922418] {CVE-2012-6544}- [bluetooth] HCI - Fix info leak in getsockopt() (Jacob Tanenbaum) [922417 922418] {CVE-2012-6544}- [net] tuntap: initialize vlan_features (Vlad Yasevich) [984524 951458]- [net] af_key: initialize satype in key_notify_policy_flush() (Thomas Graf) [981225 981227] {CVE-2013-2237}- [usb] uhci: fix for suspend of virtual HP controller (Gopal) [982697 960026]- [usb] uhci: Remove PCI dependencies from uhci-hub (Gopal) [982697 960026]- [netdrv] bnx2x: Change MDIO clock settings (Michal Schmidt) [982116 901747]- [scsi] st: Take additional queue ref in st_probe (Tomas Henzl) [979293 927988]- [kernel] audit: wait_for_auditd() should use TASK_UNINTERRUPTIBLE (Oleg Nesterov) [982472 962976]- [kernel] audit: avoid negative sleep durations (Oleg Nesterov) [982472 962976]- [fs] ext4/jbd2: dont wait (forever) for stale tid caused by wraparound (Eric Sandeen) [963557 955807]- [fs] jbd: dont wait (forever) for stale tid caused by wraparound (Eric Sandeen) [963557 955807]- [fs] ext4: fix waiting and sending of a barrier in ext4_sync_file() (Eric Sandeen) [963557 955807]- [fs] jbd2: Add function jbd2_trans_will_send_data_barrier() (Eric Sandeen) [963557 955807]- [fs] jbd2: fix sending of data flush on journal commit (Eric Sandeen) [963557 955807]- [fs] ext4: fix fdatasync() for files with only i_size changes (Eric Sandeen) [963557 955807]- [fs] ext4: Initialize fsync transaction ids in ext4_new_inode() (Eric Sandeen) [963557 955807]- [fs] ext4: Rewrite __jbd2_log_start_commit logic to match upstream (Eric Sandeen) [963557 955807]- [net] bridge: Set vlan_features to allow offloads on vlans (Vlad Yasevich) [984524 951458]- [virt] virtio-net: initialize vlan_features (Vlad Yasevich) [984524 951458]- [mm] swap: avoid read_swap_cache_async() race to deadlock while waiting on discard I/O completion (Rafael Aquini) [977668 827548]- [dma] ioat: Fix excessive CPU utilization (John Feeney) [982758 883575]- [fs] vfs: revert most of dcache remove d_mounted (Ian Kent) [974597 907512]- [fs] xfs: don't free EFIs before the EFDs are committed (Carlos Maiolino) [975578 947582]- [fs] xfs: pass shutdown method into xfs_trans_ail_delete_bulk (Carlos Maiolino) [975576 805407]- [net] ipv6: bind() use stronger condition for bind_conflict (Flavio Leitner) [989923 917872]- [net] tcp: bind() use stronger condition for bind_conflict (Flavio Leitner) [977680 894683]- [x86] remove BUG_ON(TS_USEDFPU) in __sanitize_i387_state() (Oleg Nesterov) [956054 920445]- [fs] coredump: ensure the fpu state is flushed for proper multi-threaded core dump (Oleg Nesterov) [956054 920445][2.6.32-358.17.1]- [net] ipv4: fix invalid free in ip_cmsg_send() callers (Petr Matousek) [980144 979788] {CVE-2013-2224}- [net] sctp: Use correct sideffect command in duplicate cookie handling (Daniel Borkmann) [976571 963843] {CVE-2013-2206}- [virt] kvm: limit difference between kvmclock updates (Marcelo Tosatti) [979912 952174][2.6.32-358.16.1]- [net] ipv6: ip6_sk_dst_check() must not assume ipv6 dst (Jiri Pirko) [981558 981559]- [x86] Revert: Allow greater than 1TB of RAM on AMD x86_64 sytems (Larry Woodman) [982703 970735]- [x86] Revert: Prevent panic in init_memory_mapping() when booting more than 1TB on AMD systems (Larry Woodman) [982703 970735]- [mm] reinstate the first-fit scheme for arch_get_unmapped_area_topdown() (Rafael Aquini) [982571 980273][2.6.32-358.15.1]- [mm] block: optionally snapshot page contents to provide stable pages during write (Rafael Aquini) [981177 951937]- [mm] only enforce stable page writes if the backing device requires it (Rafael Aquini) [981177 951937]- [mm] bdi: allow block devices to say that they require stable page writes (Rafael Aquini) [981177 951937]- [mm] fix writeback_in_progress() (Rafael Aquini) [981177 951937]- [kernel] sched: Do not account bogus utime (Stanislaw Gruszka) [959930 912662]- [kernel] sched: Avoid cputime scaling overflow (Stanislaw Gruszka) [959930 912662]- [char] n_tty: Remove BUG_ON from n_tty_read() (Stanislaw Gruszka) [982496 848085]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-1173");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-1173.html");
script_cve_id("CVE-2012-6544","CVE-2013-2206","CVE-2013-2224","CVE-2013-2232","CVE-2013-2146","CVE-2013-2237");
script_tag(name:"cvss_base", value:"6.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.18.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

