# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0504.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122349");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:17:17 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0504");
script_tag(name: "insight", value: "ELSA-2010-0504 -  kernel security and bug fix update - [2.6.18-194.8.1.0.1.el5]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- Add entropy support to igb (John Sobecki) [orabug 7607479]- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]- [NET] Add xen pv/bonding netconsole support (Tina Yang) [orabug 6993043] [bz 7258]- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [nfsd] fix failure of file creation from hpux client (Wen gang Wang) [orabug 7579314]- [qla] fix qla not to query hccr (Guru Anbalagane) [Orabug 8746702]- [net] bonding: fix xen+bonding+netconsole panic issue (Joe Jin) [orabug 9504524]- [rds] Patch rds to 1.4.2-14 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to()- [mm] Enahance shrink_zone patch allow full swap utilization, and also be NUMA-aware (John Sobecki, Chris Mason, Herbert van den Bergh) [orabug 9245919][2.6.18-194.8.1.el5]- [net] cnic: fix bnx2x panic w/multiple interfaces enabled (Stanislaw Gruszka) [607087 602402][2.6.18-194.7.1.el5]- [virt] don't compute pvclock adjustments if we trust tsc (Glauber Costa) [601080 570824]- [virt] add a global synchronization point for pvclock (Glauber Costa) [601080 570824]- [virt] enable pvclock flags in vcpu_time_info structure (Glauber Costa) [601080 570824]- [misc] add atomic64_cmpxcgh to x86_64 include files (Glauber Costa) [601080 570824]- [x86] grab atomic64 types from upstream (Glauber Costa) [601080 570824][2.6.18-194.6.1.el5]- [fs] gfs2: fix permissions checking for setflags ioctl (Steven Whitehouse) [595580 595399] {CVE-2010-1641}- [mm] clear page errors when issuing a fresh read of page (Rik van Riel) [599739 590763]- [misc] keys: do not find already freed keyrings (Vitaly Mayatskikh) [585099 585100] {CVE-2010-1437}- [net] sctp: file must be valid before setting timeout (Jiri Pirko) [598355 578261]- [net] tg3: fix panic in tg3_interrupt (John Feeney) [600498 569106]- [net] e1000/e1000e: implement simple interrupt moderation (Andy Gospodarek) [599332 586416]- [net] cnic: Fix crash during bnx2x MTU change (Stanislaw Gruszka) [596385 582367]- [net] bxn2x: add dynamic lro disable support (Stanislaw Gruszka) [596385 582367]- [net] implement dev_disable_lro api for RHEL5 (Stanislaw Gruszka) [596385 582367]- [x86_64] fix time drift due to faulty lost tick tracking (Ulrich Obergfell) [601090 579711]- [net] neigh: fix state transitions via Netlink request (Jiri Pirko) [600215 485903]- [mm] fix hugepage corruption using vm.drop_caches (Larry Woodman) [599737 579469]- [nfs] don't unhash dentry in nfs_lookup_revalidate (Jeff Layton) [596384 582321]- [fs] remove unneccessary f_ep_lock from fasync_helper (Lachlan McIlroy) [599730 567479]- [xen] set hypervisor present CPUID bit (Paolo Bonzini) [599734 573771][2.6.18-194.5.1.el5]- [net] bonding: fix broken multicast with round-robin mode (Andy Gospodarek) [594057 570645]- [net] tg3: fix INTx fallback when MSI fails (Steve Best) [592844 587666]- [net] sched: fix SFQ qdisc crash w/limit of 2 packets (Jiri Pirko) [594054 579774]- [nfs] revert retcode check in nfs_revalidate_mapping() (Jeff Layton) [594061 557423]- [misc] futex: handle futex value corruption gracefully (Jerome Marchand) [563093 480396] {CVE-2010-0622}- [misc] futex: handle user space corruption gracefully (Jerome Marchand) [563093 480396] {CVE-2010-0622}- [misc] futex: fix fault handling in futex_lock_pi (Jerome Marchand) [563093 480396] {CVE-2010-0622}- [net] e1000: fix WoL init when WoL disabled in EEPROM (Dean Nelson) [591493 568561]- [virtio] fix GFP flags passed by virtio balloon driver (Amit Shah) [591611 584683]- [net] sctp: fix skb_over_panic w/too many unknown params (Neil Horman) [584657 584658] {CVE-2010-1173}- [acpi] fix WARN on unregister in power meter driver (Matthew Garrett) [592846 576246]- [mm] keep get_unmapped_area_prot functional (Danny Feng) [556709 556710] {CVE-2010-0291}- [mm] switch do_brk to get_unmapped_area (Danny Feng) [556709 556710] {CVE-2010-0291}- [mm] take arch_mmap_check into get_unmapped_area (Danny Feng) [556709 556710] {CVE-2010-0291}- [mm] get rid of open-coding in ia64_brk (Danny Feng) [556709 556710] {CVE-2010-0291}- [mm] unify sys_mmap* functions (Danny Feng) [556709 556710] {CVE-2010-0291}- [mm] kill ancient cruft in s390 compat mmap (Danny Feng) [556709 556710] {CVE-2010-0291}- [mm] fix pgoff in have to relocate case of mremap (Danny Feng) [556709 556710] {CVE-2010-0291}- [mm] fix the arch checks in MREMAP_FIXED case (Danny Feng) [556709 556710] {CVE-2010-0291}- [mm] fix checks for expand-in-place mremap (Danny Feng) [556709 556710] {CVE-2010-0291}- [mm] add new vma_expandable helper function (Danny Feng) [556709 556710] {CVE-2010-0291}- [mm] move MREMAP_FIXED into its own header (Danny Feng) [556709 556710] {CVE-2010-0291}- [mm] move locating vma code and checks on it (Danny Feng) [556709 556710] {CVE-2010-0291}[2.6.18-194.4.1.el5]- [acpi] warn on hot-add of memory exceeding 4G boundary (Prarit Bhargava) [587957 571544]- [net] tipc: fix various oopses in uninitialized code (Neil Horman) [578058 558693] {CVE-2010-1187}- [block] cfq-iosched: fix IOPRIO_CLASS_IDLE accounting (Jeff Moyer) [588219 574285]- [block] cfq-iosched: async queue allocation per priority (Jeff Moyer) [588219 574285]- [block] cfq-iosched: fix async queue behaviour (Jeff Moyer) [588219 574285]- [block] cfq-iosched: propagate down request sync flag (Jeff Moyer) [588219 574285]- [block] introduce the rq_is_sync macro (Jeff Moyer) [588219 574285]- [fs] vfs: fix LOOKUP_FOLLOW on automount symlinks (Jeff Layton) [567815 567816] {CVE-2010-1088}- [nfs] fix an oops when truncating a file (Jeff Layton) [567194 567195] {CVE-2010-1087}- [fs] fix kernel oops while copying from ext3 to gfs2 (Abhijith Das) [586008 555754] {CVE-2010-1436}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0504");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0504.html");
script_cve_id("CVE-2010-0291","CVE-2010-0622","CVE-2010-1087","CVE-2010-1088","CVE-2010-1173","CVE-2010-1187","CVE-2010-1436","CVE-2010-1437","CVE-2010-1641");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.8.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.8.1.0.1.el5~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.8.1.0.1.el5PAE~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.8.1.0.1.el5debug~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.8.1.0.1.el5xen~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.8.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.8.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.8.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.8.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

