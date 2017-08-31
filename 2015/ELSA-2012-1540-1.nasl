# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-1540-1.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123773");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:08:20 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-1540-1");
script_tag(name: "insight", value: "ELSA-2012-1540-1 -  kernel security, bug fix, and enhancement update - kernel[2.6.18-308.24.1.0.1.el5]- [kernel] Initialize the local uninitialized variable stats. [orabug 14051367]- [fs] JBD:make jbd support 512B blocks correctly for ocfs2. [orabug 13477763]- [x86 ] fix fpu context corrupt when preempt in signal context [orabug 14038272]- [mm] fix hugetlb page leak (Dave McCracken) [orabug 12375075]- fix ia64 build error due to add-support-above-32-vcpus.patch(Zhenzhong Duan)- [x86] use dynamic vcpu_info remap to support more than 32 vcpus (Zhenzhong Duan)- [x86] Fix lvt0 reset when hvm boot up with noapic param- [scsi] remove printks when doing I/O to a dead device (John Sobecki, Chris Mason) [orabug 12342275]- [char] ipmi: Fix IPMI errors due to timing problems (Joe Jin) [orabug 12561346]- [scsi] Fix race when removing SCSI devices (Joe Jin) [orabug 12404566]- [net] net: Redo the broken redhat netconsole over bonding (Tina Yang) [orabug 12740042]- [fs] nfs: Fix __put_nfs_open_context() NULL pointer panic (Joe Jin) [orabug 12687646]- [scsi] fix scsi hotplug and rescan race [orabug 10260172]- fix filp_close() race (Joe Jin) [orabug 10335998]- make xenkbd.abs_pointer=1 by default [orabug 67188919]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- [net] Enable entropy for bnx2,bnx2x,e1000e,igb,ixgb,ixgbe,ixgbevf (John Sobecki) [orabug 10315433]- [NET] Add xen pv netconsole support (Tina Yang) [orabug 6993043] [bz 7258]- [mm] Patch shrink_zone to yield during severe mempressure events, avoiding hangs and evictions (John Sobecki,Chris Mason) [orabug 6086839]- [mm] Enhance shrink_zone patch allow full swap utilization, and also be NUMA-aware (John Sobecki,Chris Mason,Herbert van den Bergh) [orabug 9245919]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [rds] Patch rds to 1.4.2-20 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to()- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson) [orabug 9107465]- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson) [orabug 9764220]- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]- fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro, Guru Anbalagane) [orabug 6124033]- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]- [ib] fix memory corruption (Andy Grover) [orabug 9972346][2.6.18-308.24.1.el5]- Revert: [scsi] sg: fix races during device removal (Ewan Milne) [868950 861004][2.6.18-308.23.1.el5]- [net] bnx2x: Add remote-fault link detection (Alexander Gordeev) [870120 796905]- [net] bnx2x: Cosmetic changes (Alexander Gordeev) [870120 796905]- [net] rds-ping cause kernel panic (Alexander Gordeev) [822755 822756] {CVE-2012-2372}- [xen] add guest address range checks to XENMEM_exchange handlers (Igor Mammedov) [878033 878034] {CVE-2012-5513}- [xen] x86/physmap: Prevent incorrect updates of m2p mappings (Igor Mammedov) [870148 870149] {CVE-2012-4537}- [xen] VCPU/timer: Dos vulnerability prev overflow in calculations (Igor Mammedov) [870150 870151] {CVE-2012-4535}- [scsi] sg: fix races during device removal (Ewan Milne) [868950 861004][2.6.18-308.22.1.el5]- [net] bonding: fix link down handling in 802.3ad mode (Andy Gospodarek) [877943 782866][2.6.18-308.21.1.el5]- [fs] ext4: race-cond protect for convert_unwritten_extents_endio (Lukas Czerner) [869910 869911] {CVE-2012-4508}- [fs] ext4: serialize fallocate w/ ext4_convert_unwritten_extents (Lukas Czerner) [869910 869911] {CVE-2012-4508}- [fs] ext4: flush the i_completed_io_list during ext4_truncate (Lukas Czerner) [869910 869911] {CVE-2012-4508}- [net] WARN if struct ip_options was allocated directly by kmalloc (Jiri Pirko) [874973 872612]- [net] ipv4: add RCU protection to inet->opt (Jiri Pirko) [872113 855302] {CVE-2012-3552}- [scsi] qla2xx: Dont toggle inter bits after IRQ lines attached (Chad Dupuis) [870118 800708]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-1540-1");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-1540-1.html");
script_cve_id("CVE-2012-2372","CVE-2012-3552","CVE-2012-4508","CVE-2012-4535","CVE-2012-4537","CVE-2012-5513");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.24.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.24.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.24.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.24.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.24.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.24.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.24.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.24.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.24.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.24.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~308.24.1.0.1.el5~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~308.24.1.0.1.el5PAE~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~308.24.1.0.1.el5debug~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~308.24.1.0.1.el5xen~1.4.10~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~308.24.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~308.24.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~308.24.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~308.24.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

