# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0723.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122315");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:16:38 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0723");
script_tag(name: "insight", value: "ELSA-2010-0723 -  kernel security and bug fix update - [2.6.18-194.17.1.0.1.el5] - [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514] - Add entropy support to igb (John Sobecki) [orabug 7607479] - [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332] - [NET] Add xen pv/bonding netconsole support (Tina Yang) [orabug 6993043] [bz 7258] - [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839] - fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042] - [nfsd] fix failure of file creation from hpux client (Wen gang Wang) [orabug 7579314] - [qla] fix qla not to query hccr (Guru Anbalagane) [Orabug 8746702] - [net] bonding: fix xen+bonding+netconsole panic issue (Joe Jin) [orabug 9504524] - [rds] Patch rds to 1.4.2-14 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to() - [mm] Enhance shrink_zone patch allow full swap utilization, and also be NUMA-aware (John Sobecki, Chris Mason, Herbert van den Bergh) [orabug 9245919] - [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson) [orabug 9107465] - [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson) [orabug 9764220] - Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615] - fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro, Guru Anbalagane) [orabug 6124033] - [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208] - [ib] fix memory corruption (Andy Grover) [orabug 9972346] [2.6.18-194.17.1.el5] - Syncing following patch from branched build: - [misc] make compat_alloc_user_space() incorporate the access_ok() (Don Howard) [634463 634464] {CVE-2010-3081} [2.6.18-194.16.1.el5] - [fs] xfs: fix missing untrusted inode lookup tag (Dave Chinner) [624366 607032] {CVE-2010-2943} [2.6.18-194.15.1.el5] - [net] cxgb3: don't flush workqueue if called from wq (Doug Ledford) [630978 630124] - [net] cxgb3: get fatal parity error status on interrupt (Doug Ledford) [630978 630124] - [net] cxgb3: clear fatal parity error register on init (Doug Ledford) [630978 630124] - [net] cxgb3: add define for fatal parity error bit (Doug Ledford) [630978 630124] [2.6.18-194.14.1.el5] - [s390] dasd: force online does not work (Hendrik Brueckner) [627194 619466] - [s390] dasd: allocate fallback cqr for reserve/release (Hendrik Brueckner) [627195 619465] - [fs] xfs: fix untrusted inode number lookup (Dave Chinner) [629219 624862] - [net] sched: fix some kernel memory leaks (Jiri Pirko) [624904 624638] {CVE-2010-2942} - [usb] fix usbfs information leak (Eugene Teo) [566628 566629] {CVE-2010-1083} - [fs] xfs: rename XFS_IGET_BULKSTAT to XFS_IGET_UNTRUSTED (Dave Chinner) [624366 607032] {CVE-2010-2943} - [fs] xfs: validate untrusted inode numbers during lookup (Dave Chinner) [624366 607032] {CVE-2010-2943} - [fs] xfs: always use iget in bulkstat (Dave Chinner) [624366 607032] {CVE-2010-2943} [2.6.18-194.13.1.el5] - [xen] fix guest crash on non-EPT machine may crash host (Paolo Bonzini) [621429 621430] {CVE-2010-2938} - [fs] ext4: consolidate in_range definitions (Eric Sandeen) [624331 624332] {CVE-2010-3015} - [mm] add option to skip ZERO_PAGE mmap of /dev/zero (Larry Woodman) [623141 619541] - [net] bonding: check if clients MAC addr has changed (Flavio Leitner) [623143 610234] - [net] sctp: fix length checks (Neil Horman) [624369 605305] - [xen] bring back VMXE/SVME flags (Andrew Jones) [624365 570091] - Syncing following patches from branched builds: - [mm] accept an abutting stack segment (Jiri Pirko) [607857 607858] {CVE-2010-2240} - [mm] pass correct mm when growing stack (Jiri Pirko) [607857 607858] {CVE-2010-2240} - [mm] fix up some user-visible effects of stack guard page (Jiri Pirko) [607857 607858] {CVE-2010-2240} - [mm] fix page table unmap for stack guard page properly (Jiri Pirko) [607857 607858] {CVE-2010-2240} - [mm] fix missing unmap for stack guard page failure case (Jiri Pirko) [607857 607858] {CVE-2010-2240} - [mm] keep a guard page below a grow-down stack segment (Jiri Pirko) [607857 607858] {CVE-2010-2240}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0723");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0723.html");
script_cve_id("CVE-2010-1083","CVE-2010-2492","CVE-2010-2798","CVE-2010-2938","CVE-2010-2942","CVE-2010-2943","CVE-2010-3015");
script_tag(name:"cvss_base", value:"7.9");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:N");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.17.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.17.1.0.1.el5~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.17.1.0.1.el5PAE~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.17.1.0.1.el5debug~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.17.1.0.1.el5xen~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.17.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.17.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.17.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.17.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

