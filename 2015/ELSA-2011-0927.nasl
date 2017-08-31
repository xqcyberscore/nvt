# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-0927.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122132");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:13:35 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-0927");
script_tag(name: "insight", value: "ELSA-2011-0927 -  kernel security and bug fix update - [2.6.18-238.19.1.0.1.el5]- [scsi] remove printk's when doing I/O to a dead device (John Sobecki, Chris Mason) [orabug 12342275]- [char] ipmi: Fix IPMI errors due to timing problems (Joe Jin) [orabug 12561346]- [scsi] Fix race when removing SCSI devices (Joe Jin) [orabug 12404566]- bonding: reread information about speed and duplex when interface goes up (John Haxby) [orabug 11890822]- [scsi] fix scsi hotplug and rescan race [orabug 10260172]- fix filp_close() race (Joe Jin) [orabug 10335998]- fix missing aio_complete() in end_io (Joel Becker) [orabug 10365195]- make xenkbd.abs_pointer=1 by default [orabug 67188919]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- [net] Enable entropy for bnx2,bnx2x,e1000e,igb,ixgb,ixgbe,ixgbevf (John Sobecki) [orabug 10315433]- [NET] Add xen pv netconsole support (Tina Yang) [orabug 6993043] [bz 7258]- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [rds] Patch rds to 1.4.2-20 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to()- [qla] fix qla not to query hccr (Guru Anbalagane) [Orabug 8746702]- [nfs] too many getattr and access calls after direct I/O [orabug 9348191]- [xen] PVHVM guest with PoD crashes under memory pressure (Chuck Anderson) [orabug 9107465]- [xen] PV guest with FC HBA hangs during shutdown (Chuck Anderson) [orabug 9764220]- Support 256GB+ memory for pv guest (Mukesh Rathor) [orabug 9450615]- fix overcommit memory to use percpu_counter for el5 (KOSAKI Motohiro, Guru Anbalagane) [orabug 6124033]- [ipmi] make configurable timeouts for kcs of ipmi [orabug 9752208]- [ib] fix memory corruption (Andy Grover) [orabug 9972346]- [aio] patch removes limit on number of retries (Srinivas Eeda) [orabug 10044782]- [loop] Do not call loop_unplug for not configured loop device (orabug 10314497)[2.6.18-238.19.1.el5]- Revert: [xen] hvm: svm support cleanups (Andrew Jones) [703715 702657] {CVE-2011-1780}- Revert: [xen] hvm: secure svm_cr_access (Andrew Jones) [703715 702657] {CVE-2011-1780}- Revert: [xen] let __get_instruction_length always read into own buffer (Paolo Bonzini) [719066 717742]- Revert: [xen] remove unused argument to __get_instruction_length (Phillip Lougher) [719066 717742]- Revert: [xen] prep __get_instruction_length_from_list for partial buffers (Paolo Bonzini) [719066 717742]- Revert: [xen] disregard trailing bytes in an invalid page (Paolo Bonzini) [719066 717742][2.6.18-238.18.1.el5]- [xen] disregard trailing bytes in an invalid page (Paolo Bonzini) [719066 717742]- [xen] prep __get_instruction_length_from_list for partial buffers (Paolo Bonzini) [719066 717742]- [xen] remove unused argument to __get_instruction_length (Phillip Lougher) [719066 717742]- [xen] let __get_instruction_length always read into own buffer (Paolo Bonzini) [719066 717742][2.6.18-238.17.1.el5]- [net] bluetooth: l2cap and rfcomm: fix info leak to userspace (Thomas Graf) [703020 703021] {CVE-2011-2492}- [net] inet_diag: fix inet_diag_bc_audit data validation (Thomas Graf) [714538 714539] {CVE-2011-2213}- [misc] signal: fix kill signal spoofing issue (Oleg Nesterov) [690030 690031] {CVE-2011-1182}- [fs] proc: fix signedness issue in next_pidmap (Oleg Nesterov) [697826 697827] {CVE-2011-1593}- [char] agp: fix OOM and buffer overflow (Jerome Marchand) [699009 699010] {CVE-2011-1746}- [char] agp: fix arbitrary kernel memory writes (Jerome Marchand) [699005 699006] {CVE-2011-2022 CVE-2011-1745}- [infiniband] core: Handle large number of entries in poll CQ (Jay Fenlason) [668370 668371] {CVE-2011-1044 CVE-2010-4649}- [infiniband] core: fix panic in ib_cm:cm_work_handler (Jay Fenlason) [679995 679996] {CVE-2011-0695}- [fs] validate size of EFI GUID partition entries (Anton Arapov) [703027 703028] {CVE-2011-1776}[2.6.18-238.16.1.el5]- [xen] hvm: secure vmx cpuid (Andrew Jones) [706324 706323] {CVE-2011-1936}- [xen] hvm: secure svm_cr_access (Andrew Jones) [703715 702657] {CVE-2011-1780}- [xen] hvm: svm support cleanups (Andrew Jones) [703715 702657] {CVE-2011-1780}[2.6.18-238.15.1.el5]- [block] cciss: reading a write only register causes a hang (Phillip Lougher) [713948 696153]- [fs] gfs2: fix resource group bitmap corruption (Robert S Peterson) [711519 690555]- [net] sctp: fix calc of INIT/INIT-ACK chunk length to set (Thomas Graf) [695384 695385] {CVE-2011-1573}- [fs] xfs: prevent leaking uninit stack memory in FSGEOMETRY_V1 p2 (Phillip Lougher) [677265 677266] {CVE-2011-0711}- [fs] xfs: prevent leaking uninit stack memory in FSGEOMETRY_V1 (Phillip Lougher) [677265 677266] {CVE-2011-0711}- [net] core: Fix memory leak/corruption on VLAN GRO_DROP (Herbert Xu) [695174 691565] {CVE-2011-1576}- [pci] SRIOV: release VF BAR resources when device is hot unplug (Don Dutile) [707899 698879]- [scsi] iscsi_tcp: fix iscsi's sk_user_data access (Mike Christie) [703056 677703]- [message] mptfusion: add ioc_reset_in_progress reset in SoftReset (Tomas Henzl) [712034 662160][2.6.18-238.14.1.el5]- [input] evdev: implement proper locking (Marc Milgram) [710426 680561]- [input] evdev: rename list to client in handlers (Marc Milgram) [710426 680561][2.6.18-238.13.1.el5]- [fs] gfs2: fix processes waiting on already-available inode glock (Phillip Lougher) [709767 694669]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-0927");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-0927.html");
script_cve_id("CVE-2010-4649","CVE-2011-0695","CVE-2011-0711","CVE-2011-1044","CVE-2011-1182","CVE-2011-1573","CVE-2011-1576","CVE-2011-1593","CVE-2011-1745","CVE-2011-1746","CVE-2011-1776","CVE-2011-1936","CVE-2011-2022","CVE-2011-2213","CVE-2011-2492");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~238.19.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~238.19.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~238.19.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~238.19.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~238.19.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~238.19.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~238.19.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~238.19.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~238.19.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~238.19.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.19.1.0.1.el5~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.19.1.0.1.el5PAE~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.19.1.0.1.el5debug~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~238.19.1.0.1.el5xen~1.4.8~2.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.19.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.19.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.19.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~238.19.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

