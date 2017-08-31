# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0981.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123347");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:02:35 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0981");
script_tag(name: "insight", value: "ELSA-2014-0981 -  kernel security, bug fix, and enhancement update - [2.6.32-431.23.3]- [netdrv] pppol2tp: fail when socket option level is not SOL_PPPOL2TP [1119461 1119462] {CVE-2014-4943}[2.6.32-431.23.2]- [kernel] utrace: force IRET path after utrace_finish_vfork() (Oleg Nesterov) [1115932 1115933] {CVE-2014-4699}[2.6.32-431.23.1]- [net] ip_tunnel: fix ip_tunnel_find to return NULL in case the tunnel is not there (Jiri Pirko) [1107931 1104503]- [netdrv] bnx2x: Fix kernel crash and data miscompare after EEH recovery (Michal Schmidt) [1109269 1029600]- [netdrv] bnx2x: Adapter not recovery from EEH error injection (Michal Schmidt) [1109269 1029600]- [scsi] qla2xxx: Don't check for firmware hung during the reset context for ISP82XX (Chad Dupuis) [1110658 1054299]- [scsi] qla2xxx: Clear loop_id for ports that are marked lost during fabric scanning (Chad Dupuis) [1110658 1054299]- [scsi] qla2xxx: Issue abort command for outstanding commands during cleanup when only firmware is alive (Chad Dupuis) [1110658 1054299]- [scsi] qla2xxx: Reduce the time we wait for a command to complete during SCSI error handling (Chad Dupuis) [1110658 1054299]- [scsi] qla2xxx: Avoid escalating the SCSI error handler if the command is not found in firmware (Chad Dupuis) [1110658 1054299]- [scsi] qla2xxx: Set host can_queue value based on available resources (Chad Dupuis) [1110658 1054299]- [net] filter: prevent nla extensions to peek beyond the end of the message (Jiri Benc) [1096778 1096779] {CVE-2014-3144 CVE-2014-3145}- [net] bridge: add empty br_mdb_init() and br_mdb_uninit() definitions (Vlad Yasevich) [1106472 1097915]- [net] bridge: Correctly unregister MDB rtnetlink handlers (Vlad Yasevich) [1106472 1097915]- [net] rds: prevent dereference of a NULL device in rds_iw_laddr_check (Radomir Vrbovsky) [1083276 1083277] {CVE-2014-2678}- [s390] crypto: fix aes, des ctr mode concurrency finding (Hendrik Brueckner) [1110168 1096328]- [s390] crypto: fix des and des3_ede ctr concurrency issue (Hendrik Brueckner) [1109885 1065404]- [s390] crypto: fix des and des3_ede cbc concurrency issue (Hendrik Brueckner) [1109883 1065398]- [kernel] futex: Forbid uaddr == uaddr2 in futex_wait_requeue_pi() (Mateusz Guzik) [1097759 1097760] {CVE-2012-6647}- [libata] ahci: accommodate tag ordered controller (David Milburn) [1099725 1083748]- [net] mac80211: crash dues to AP powersave TX vs. wakeup race (Jacob Tanenbaum) [1083531 1083532] {CVE-2014-2706}- [netdrv] ath9k: tid->sched race in ath_tx_aggr_sleep() (Jacob Tanenbaum) [1083249 1083250] {CVE-2014-2672}- [kernel] hrtimer: Prevent all reprogramming if hang detected (Prarit Bhargava) [1096059 1075805]- [net] ipv4: current group_info should be put after using (Jiri Benc) [1087412 1087414] {CVE-2014-2851}- [kernel] tracing: Reset ring buffer when changing trace_clocks (Marcelo Tosatti) [1093984 1018138]- [net] rds: dereference of a NULL device (Jacob Tanenbaum) [1079218 1079219] {CVE-2013-7339}- [s390] crypto: fix concurrency issue in aes-ctr mode (Hendrik Brueckner) [1110169 1063478]- [net] ipv4: processing ancillary IP_TOS or IP_TTL (Francesco Fusco) [1094403 990694]- [net] ipv4: IP_TOS and IP_TTL can be specified as ancillary data (Francesco Fusco) [1094403 990694]- [s390] crypto: Fix aes-xts parameter corruption (Hendrik Brueckner) [1110170 1043540]- [fs] ext3: pass custom EOF to generic_file_llseek_size() (Eric Sandeen) [1103068 1007459]- [fs] ext4: use core vfs llseek code for dir seeks (Eric Sandeen) [1103068 1007459]- [fs] vfs: allow custom EOF in generic_file_llseek code (Eric Sandeen) [1103068 1007459]- [fs] ext3: return 32/64-bit dir name hash according to usage type (Eric Sandeen) [1103068 1007459]- [fs] ext4: replace cut'n'pasted llseek code with generic_file_llseek_size (Eric Sandeen) [1103068 1007459]- [fs] vfs: add generic_file_llseek_size (Eric Sandeen) [1103068 1007459]- [net] bridge: disable snooping if there is no querier (Vlad Yasevich) [1090749 1090670]- [net] Revert 'bridge: only expire the mdb entry when query is received' (Vlad Yasevich) [1090749 1090670]- [net] Revert 'bridge: fix some kernel warning in multicast timer' (Vlad Yasevich) [1090749 1090670]- [net] Revert 'bridge: do not call setup_timer() multiple times' (Vlad Yasevich) [1090749 1090670]- [net] Revert 'bridge: update mdb expiration timer upon reports' (Vlad Yasevich) [1090749 1090670]- [kernel] futex: Make lookup_pi_state more robust (Jerome Marchand) [1104516 1104517] {CVE-2014-3153}- [kernel] futex: Always cleanup owner tid in unlock_pi (Jerome Marchand) [1104516 1104517] {CVE-2014-3153}- [kernel] futex: Validate atomic acquisition in futex_lock_pi_atomic() (Jerome Marchand) [1104516 1104517] {CVE-2014-3153}- [kernel] futex: prevent requeue pi on same futex (Jerome Marchand) [1104516 1104517] {CVE-2014-3153}- [fs] autofs4: fix device ioctl mount lookup (Ian Kent) [1069630 999708]- [fs] vfs: introduce kern_path_mountpoint() (Ian Kent) [1069630 999708]- [fs] vfs: rename user_path_umountat() to user_path_mountpoint_at() (Ian Kent) [1069630 999708]- [fs] vfs: massage umount_lookup_last() a bit to reduce nesting (Ian Kent) [1069630 999708]- [fs] vfs: allow umount to handle mountpoints without revalidating them (Ian Kent) [1069630 999708]- Revert: [fs] vfs: allow umount to handle mountpoints without revalidating them (Ian Kent) [1069630 999708]- Revert: [fs] vfs: massage umount_lookup_last() a bit to reduce nesting (Ian Kent) [1069630 999708]- Revert: [fs] vfs: rename user_path_umountat() to user_path_mountpoint_at() (Ian Kent) [1069630 999708]- Revert: [fs] vfs: introduce kern_path_mountpoint() (Ian Kent) [1069630 999708]- Revert: [fs] autofs4: fix device ioctl mount lookup (Ian Kent) [1069630 999708]- [block] floppy: don't write kernel-only members to FDRAWCMD ioctl output (Denys Vlasenko) [1094308 1094310] {CVE-2014-1738 CVE-2014-1737}- [block] floppy: ignore kernel-only members in FDRAWCMD ioctl input (Denys Vlasenko) [1094308 1094310] {CVE-2014-1738 CVE-2014-1737}- [fs] vfs: fix autofs/afs/etc magic mountpoint breakage (Frantisek Hrbata) [1094370 1079347] {CVE-2014-0203}[2.6.32-431.22.1]- [fs] cifs: Check if prefixpath starts with ' in cifs_parse_mount_options (Sachin Prabhu) [1107503 1104268]- [virt] kvm: enable PCI multiple-segments for pass-through device (Michael S. Tsirkin) [1103972 1103471]- [fs] GFS2: Lock i_mutex and use a local gfs2_holder for fallocate (Robert S Peterson) [1102313 1061910][2.6.32-431.21.1]- [kvm] mmu: fix incorrect check of guest cr4 bits (Bandan Das) [1103821 1007164]- [drm] nouveau: fix nasty bug which can clobber SOR0's clock setup (Ben Skeggs) [1100574 1095796]- [net] tcp: tsq: restore minimal amount of queueing (Jiri Pirko) [1103825 1044053]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0981");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0981.html");
script_cve_id("CVE-2014-2851","CVE-2013-7339","CVE-2014-3144","CVE-2014-3145","CVE-2014-2678","CVE-2012-6647","CVE-2014-2672","CVE-2014-2706");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.23.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.23.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.23.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.23.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.23.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.23.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.23.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.23.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.23.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.23.3.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

