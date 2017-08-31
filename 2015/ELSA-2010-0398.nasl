# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0398.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122359");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:17:31 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0398");
script_tag(name: "insight", value: "ELSA-2010-0398 -  kernel security and bug fix update - [2.6.18-194.3.1.0.1.el5]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- Add entropy support to igb (John Sobecki) [orabug 7607479]- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]- [NET] Add xen pv/bonding netconsole support (Tina Yang) [orabug 6993043] [bz 7258]- [mm] shrink_zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [nfsd] fix failure of file creation from hpux client (Wen gang Wang) [orabug 7579314]- [nfs] -revert return code check to avoid EIO (Chuck Lever, Guru Anbalagane) [Orabug 9448515]- [qla] fix qla not to query hccr (Guru Anbalagane) [Orabug 8746702]- [net] bonding: fix xen+bonding+netconsole panic issue (Joe Jin) [orabug 9504524]- [mm] Set hugepages dirty bit so vm.drop_caches does not corrupt (John Sobecki) [orabug 9461825]- [rds] Patch rds to 1.4.2-14 (Andy Grover) [orabug 9471572, 9344105] RDS: Fix BUG_ONs to not fire when in a tasklet ipoib: Fix lockup of the tx queue RDS: Do not call set_page_dirty() with irqs off (Sherman Pun) RDS: Properly unmap when getting a remote access error (Tina Yang) RDS: Fix locking in rds_send_drop_to()[2.6.18-194.3.1.el5]- [net] bnx2: fix lost MSI-X problem on 5709 NICs (John Feeney) [587799 511368][2.6.18-194.2.1.el5]- [cpu] fix boot crash in 32-bit install on AMD cpus (Bhavna Sarathy) [580846 575799][2.6.18-194.1.1.el5]- [xen] arpl on MMIO area crashes the guest (Paolo Bonzini) [572979 572982] {CVE-2010-0730}- [mm] fix boot on s390x after bootmem overlap patch (Amerigo Wang) [580838 550974]- [net] bnx2: avoid restarting cnic in some contexts (Andy Gospodarek) [581148 554706]- [iscsi] fix slow failover times (Mike Christie) [580840 570681]- [misc] kernel: fix elf load DoS on x86_64 (Danny Feng) [560552 560553] {CVE-2010-0307}- [netlink] connector: delete buggy notification code (Jiri Olsa) [561684 561685] {CVE-2010-0410}- [sound] hda_intel: avoid divide by zero in azx devices (Jaroslav Kysela) [567171 567172] {CVE-2010-1085}- [dvb] fix endless loop when decoding ULE at dvb-core (Mauro Carvalho Chehab) [569241 569242] {CVE-2010-1086}- [scsi] fnic: fix tx queue handling (Mike Christie) [580829 576709]- [fusion] mptsas: fix event_data alignment (Tomas Henzl) [580832 570000]- [edac] fix internal error message in amd64_edac driver (Bhavna Sarathy) [580836 569938]- [x86_64] fix floating point state corruption after signal (Oleg Nesterov) [580841 560891]- [mm] don't let reserved memory overlap bootmem_map (Amerigo Wang) [580838 550974]- [s390] kernel: correct TLB flush of page table entries (Hendrik Brueckner) [580839 545527]- [xen] iommu: clear IO-APIC pins on boot and shutdown (Paolo Bonzini) [580199 548201]- [xen] vtd: fix ioapic pin array (Don Dugger) [581150 563546]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0398");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0398.html");
script_cve_id("CVE-2010-0307","CVE-2010-0410","CVE-2010-0730","CVE-2010-1085","CVE-2010-1086");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.3.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.3.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.3.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.3.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.3.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.3.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.3.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.3.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.3.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.3.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.3.1.0.1.el5~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.3.1.0.1.el5PAE~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.3.1.0.1.el5debug~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~194.3.1.0.1.el5xen~1.4.7~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.3.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.3.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.3.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~194.3.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

