# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-1978.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122728");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-11-08 13:05:18 +0200 (Sun, 08 Nov 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-1978");
script_tag(name: "insight", value: "ELSA-2015-1978 -  kernel security, bug fix, and enhancement update - [3.10.0-229.20.1.OL7]- Oracle Linux certificates (Alexey Petrenko)[3.10.0-229.20.1]- Revert: [crypto] nx - Check for bogus firmware properties (Phillip Lougher) [1247127 1190103]- Revert: [crypto] nx - Moving NX-AES-CBC to be processed logic (Phillip Lougher) [1247127 1190103]- Revert: [crypto] nx - Moving NX-AES-CCM to be processed logic and sg_list bounds (Phillip Lougher) [1247127 1190103]- Revert: [crypto] nx - Moving limit and bound logic in CTR and fix IV vector (Phillip Lougher) [1247127 1190103]- Revert: [crypto] nx - Moving NX-AES-ECB to be processed logic (Phillip Lougher) [1247127 1190103]- Revert: [crypto] nx - Moving NX-AES-GCM to be processed logic (Phillip Lougher) [1247127 1190103]- Revert: [crypto] nx - Moving NX-AES-XCBC to be processed logic (Phillip Lougher) [1247127 1190103]- Revert: [crypto] nx - Fix SHA concurrence issue and sg limit bounds (Phillip Lougher) [1247127 1190103]- Revert: [crypto] nx - Fixing the limit number of bytes to be processed (Phillip Lougher) [1247127 1190103][3.10.0-229.19.1]- Revert: [fs] xfs: DIO write completion size updates race (Phillip Lougher) [1258942 1213370]- Revert: [fs] xfs: direct IO EOF zeroing needs to drain AIO (Phillip Lougher) [1258942 1213370][3.10.0-229.18.1]- [scsi] sd: split sd_init_command (Ewan Milne) [1264141 1109348]- [scsi] sd: retry discard commands (Ewan Milne) [1264141 1109348]- [scsi] sd: retry write same commands (Ewan Milne) [1264141 1109348]- [scsi] sd: don't use scsi_setup_blk_pc_cmnd for discard requests (Ewan Milne) [1264141 1109348]- [scsi] sd: don't use scsi_setup_blk_pc_cmnd for write same requests (Ewan Milne) [1264141 1109348]- [scsi] sd: don't use scsi_setup_blk_pc_cmnd for flush requests (Ewan Milne) [1264141 1109348]- [scsi] set sc_data_direction in common code (Ewan Milne) [1264141 1109348]- [scsi] restructure command initialization for TYPE_FS requests (Ewan Milne) [1264141 1109348]- [scsi] move the nr_phys_segments assert into scsi_init_io (Ewan Milne) [1264141 1109348]- [fs] xfs: remove bitfield based superblock updates (Brian Foster) [1261781 1225075]- [netdrv] ixgbe: fix X540 Completion timeout (John Greene) [1257633 1173786]- [lib] radix-tree: handle allocation failure in radix_tree_insert() (Seth Jennings) [1264142 1260613]- [crypto] nx - Fixing the limit number of bytes to be processed (Herbert Xu) [1247127 1190103]- [crypto] nx - Fix SHA concurrence issue and sg limit bounds (Herbert Xu) [1247127 1190103]- [crypto] nx - Moving NX-AES-XCBC to be processed logic (Herbert Xu) [1247127 1190103]- [crypto] nx - Moving NX-AES-GCM to be processed logic (Herbert Xu) [1247127 1190103]- [crypto] nx - Moving NX-AES-ECB to be processed logic (Herbert Xu) [1247127 1190103]- [crypto] nx - Moving limit and bound logic in CTR and fix IV vector (Herbert Xu) [1247127 1190103]- [crypto] nx - Moving NX-AES-CCM to be processed logic and sg_list bounds (Herbert Xu) [1247127 1190103]- [crypto] nx - Moving NX-AES-CBC to be processed logic (Herbert Xu) [1247127 1190103]- [crypto] nx - Check for bogus firmware properties (Herbert Xu) [1247127 1190103]- [md] raid1: extend spinlock to protect raid1_end_read_request against inconsistencies (Jes Sorensen) [1263416 1255758]- [md] raid1: fix test for 'was read error from last working device' (Jes Sorensen) [1263416 1255758]- [fs] xfs: direct IO EOF zeroing needs to drain AIO (Brian Foster) [1258942 1213370]- [fs] xfs: DIO write completion size updates race (Brian Foster) [1258942 1213370]- [fs] pnfs: Fix a memory leak when attempted pnfs fails (Steve Dickson) [1256640 1234986][3.10.0-229.17.1]- [hv] vmbus: Cleanup vmbus_establish_gpadl() (Vitaly Kuznetsov) [1262096 1211914]- [scsi] iscsi: let session recovery_tmo sysfs writes persist across recovery (Chris Leech) [1261879 1139038]- [scsi] ipr: Fix invalid array indexing for HRRQ (Gustavo Duarte) [1260625 1251184]- [scsi] ipr: Fix incorrect trace indexing (Gustavo Duarte) [1260625 1251184]- [net] netfilter: synproxy: fix sending window update to client (Phil Sutter) [1257289 1257290 1251031 1242094]- [net] netfilter: ip6t_synproxy: fix NULL pointer dereference (Phil Sutter) [1257289 1257290 1251031 1242094]- [fs] nfsv4: Always drain the slot table before re-establishing the lease (Benjamin Coddington) [1256649 1240790]- [fs] Recover from stateid-type error on SETATTR (Benjamin Coddington) [1256639 1214410]- [netdrv] virtio-net: drop NETIF_F_FRAGLIST (Jason Wang) [1247839 1247840] {CVE-2015-5156}- [x86] mm: add memory tracking to native_pmdp_get_and_clear (David Bulkow) [1263525 1227357]- [fs] dcache: d_walk() might skip too much (Denys Vlasenko) [1173812 1173813] {CVE-2014-8559}- [fs] dcache: deal with deadlock in d_walk() (Denys Vlasenko) [1173812 1173813] {CVE-2014-8559}- [fs] dcache: move d_rcu from overlapping d_child to overlapping d_alias (Denys Vlasenko) [1173812 1173813] {CVE-2014-8559}- [fs] dcache: fold try_to_ascend() into the sole remaining caller (Denys Vlasenko) [1173812 1173813] {CVE-2014-8559}[3.10.0-229.16.1]- [virt] kvm: x86: reset RVI upon system reset (Marcelo Tosatti) [1225087 1209995][3.10.0-229.15.1]- [cpufreq] intel_pstate: Fix overflow in busy_scaled due to long delay (Prarit Bhargava) [1255496 1228346]- [netdrv] be2net: avoid vxlan offloading on multichannel configs (Ivan Vecera) [1256609 1232327]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-1978");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-1978.html");
script_cve_id("CVE-2014-8559","CVE-2015-5156");
script_tag(name:"cvss_base", value:"6.1");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~229.20.1.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

