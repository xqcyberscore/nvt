# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0429.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122193");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:14:35 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0429");
script_tag(name: "insight", value: "ELSA-2011-0429 -  kernel security and bug fix update - [2.6.18-238.9.1.0.1.el5]- [scsi] fix scsi hotplug and rescan race [orabug 10260172]- fix filp_close() race (Joe Jin) [orabug 10335998]- fix missing aio_complete() in end_io (Joel Becker) [orabug 10365195]- make xenkbd.abs_pointer=1 by default [orabug 67188919]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- [net] Enable entropy for bnx2,bnx2x,e1000e,igb,ixgb,ixgbe,ixgbevf (John Sobecki) [orabug 10315433]- [NET] Add xen pv netconsole support (Tina Yang) [orabug 6993043] [bz 7258]- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [rds] Patch rds to 1.4.2-20 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to()- [qla] fix qla not to query hccr (Guru Anbalagane) [Orabug 8746702]- [nfs] too many getattr and access calls after direct I/O [orabug 9348191]- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson) [orabug 9107465]- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson) [orabug 9764220]- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]- fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro, Guru Anbalagane) [orabug 6124033]- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]- [ib] fix memory corruption (Andy Grover) [orabug 9972346]- [aio] patch removes limit on number of retries (Srinivas Eeda) [orabug 10044782]- [loop] Do not call loop_unplug for not configured loop device (orabug 10314497)[2.6.18-238.9.1.el5]- [md] dm-mpath: fix NULL deref when path parameter missing (Mike Snitzer) [683443 673058]- [md] dm-mpath: wait for pg_init completion on suspend (Mike Snitzer) [683443 673058]- [md] dm-mpath: hold io until all pg_inits completed (Mike Snitzer) [683443 673058]- [md] dm-mpath: skip activate_path for failed paths (Mike Snitzer) [683443 673058]- [md] dm-mpath: pass struct pgpath to pg init done (Mike Snitzer) [683443 673058]- [md] dm-mpath: prevent io from work queue while suspended (Mike Snitzer) [683443 673058]- [md] dm-mpath: add mutex to sync adding and flushing work (Mike Snitzer) [683443 673058]- [md] dm-mpath: flush workqueues before suspend completes (Mike Snitzer) [683443 673058][2.6.18-238.8.1.el5]- [message] mptfusion: fix msgContext in mptctl_hp_hostinfo (Tomas Henzl) [684128 646513]- [fs] nfs: fix use of slab alloc'd pages in skb frag list (Neil Horman) [682642 682643] {CVE-2011-1090}- [s390] remove task_show_regs (Danny Feng) [677852 677853] {CVE-2011-0710}- [misc] vdso: export wall_to_monotonic (Prarit Bhargava) [688312 675727]- [x86_64] Use u32, not long, to set reset vector back to 0 (Don Zickus) [682673 675258]- [misc] vmware: increase apic_calibration_diff to 10000 (Prarit Bhargava) [680350 665197][2.6.18-238.7.1.el5]- [fs] partitions: Validate map_count in Mac part tables (Danny Feng) [679283 679284] {CVE-2011-1010}- [x86] fix AMD family 0x15 guest boot issue on 64-bit host (Frank Arnold) [679747 667234]- [sound] alsa: cache mixer values on usb-audio devices (Don Zickus) [680043 678074]- [media] dvb: fix av7110 negative array offset (Mauro Carvalho Chehab) [672401 672402] {CVE-2011-0521}- [message] mptfusion: add required mptctl_release call (Tomas Henzl) [677173 660871]- [fs] nfs: pure nfs client performance using odirect (Jeff Layton) [677172 643441]- [mm] fix install_special_mapping skips security_file_mmap (Frantisek Hrbata) [662196 662197] {CVE-2010-4346}- [scsi] device_handler: fix alua_rtpg port group id check (Mike Snitzer) [681795 669961]- [net] cnic: fix big endian bug with device page tables (Steve Best) [674774 669527]- [net] gro: reset dev pointer on reuse (Andy Gospodarek) [674588 600350]- [misc] add ignore_loglevel kernel parameter (Amerigo Wang) [675665 662102]- [misc] add bootmem_debug kernel parameter (Amerigo Wang) [675665 662102]- [fs] gfs2: remove iopen glocks from cache on delete fail (Benjamin Marzinski) [675909 666080][2.6.18-238.6.1.el5]- [net] bonding: convert netpoll tx blocking to a counter (Neil Horman) [675664 659594]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0429");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0429.html");
script_cve_id("CVE-2010-4346","CVE-2011-0521","CVE-2011-0710","CVE-2011-1010","CVE-2011-1090","CVE-2011-1478");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~238.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~238.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~238.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~238.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~238.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~238.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~238.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~238.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~238.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~238.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.9.1.0.1.el5~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.9.1.0.1.el5PAE~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.9.1.0.1.el5debug~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.9.1.0.1.el5xen~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.9.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.9.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.9.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.9.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

