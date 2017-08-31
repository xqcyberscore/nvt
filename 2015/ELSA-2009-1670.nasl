# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2009-1670.nasl 6554 2017-07-06 11:53:20Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122408");
script_version("$Revision: 6554 $");
script_tag(name:"creation_date", value:"2015-10-08 14:44:45 +0300 (Thu, 08 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:53:20 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2009-1670");
script_tag(name: "insight", value: "ELSA-2009-1670 -  kernel security and bug fix update - [2.6.18-164.9.1.0.1.el5]- [xen] check to see if hypervisor supports memory reservation change (Chuck Anderson) [orabug 7556514]- Add entropy support to igb ( John Sobecki) [orabug 7607479]- [nfs] convert ENETUNREACH to ENOTCONN [orabug 7689332]- [NET] Add xen pv/bonding netconsole support (Tina yang) [orabug 6993043] [bz 7258]- [MM] shrink zone patch (John Sobecki,Chris Mason) [orabug 6086839]- fix aacraid not to reset during kexec (Joe Jin) [orabug 8516042]- [nfsd] fix failure of file creation from hpux client (Wen gang Wang) [orabug 7579314][2.6.18-164.9.1.el5]- [x86] fix stale data in shared_cpu_map cpumasks (Prarit Bhargava) [545583 541953][2.6.18-164.8.1.el5]- [xen] iommu-amd: extend loop ctr for polling completion wait (Bhavna Sarathy ) [539687 518474 526766]- [xen] iommu: add passthrough and no-intremap parameters (Bhavna Sarathy ) [539687 518474 526766]- [xen] iommu: enable amd iommu debug at run-time (Bhavna Sarathy ) [539687 518474 526766]- [xen] support interrupt remapping on M-C (Bhavna Sarathy ) [539687 518474 526766]- [xen] iommu: move iommu_setup() to setup ioapic correctly (Bhavna Sarathy ) [539687 518474 526766]- [net] bnx2x: add support for bcm8727 phy (Stanislaw Gruszka ) [540381 515716]- [x86] cpu: upstream cache fixes needed for amd m-c (Bhavna Sarathy ) [540469 526315]- [x86_64] set proc id and core id before calling fixup_dcm (Bhavna Sarathy) [540469 526315]- [x86] mce_amd: fix up threshold_bank4 creation (Bhavna Sarathy ) [540469 526315]- Revert: [net] sched: fix panic in bnx2_poll_work (John Feeney ) [539686 526481]- FP register state is corrupted during the handling a SIGSEGV (Chuck Anderson) [orabug 7708133][2.6.18-164.7.1.el5]- [xen] fix numa on magny-cours systems (Bhavna Sarathy ) [539684 526051]- [xen] fix crash with memory imbalance (Bhavna Sarathy ) [539690 526785]- [net] sched: fix panic in bnx2_poll_work (John Feeney ) [539686 526481]- [acpi] prevent duplicate dirs in /proc/acpi/processor (Matthew Garrett ) [539692 537395]- [x86] fix boot crash with < 8-core AMD Magny-cours system (Bhavna Sarathy) [539682 522215]- [x86] support amd magny-cours power-aware scheduler fix (Bhavna Sarathy ) [539680 513685]- [x86] disable NMI watchdog on CPU remove (Prarit Bhargava ) [539691 532514]- [acpi] bm_check and bm_control update (Luming Yu ) [539677 509422]- [x86_64] amd: iommu system management erratum 63 fix (Bhavna Sarathy ) [539689 531469]- [net] bnx2i/cnic: update driver version for RHEL5.5 (Mike Christie ) [537014 516233]- [x86] fix L1 cache by adding missing break (Bhavna Sarathy ) [539688 526770]- [x86] amd: fix hot plug cpu issue on 32-bit magny-cours (Bhavna Sarathy ) [539688 526770]- [acpi] disable ARB_DISABLE on platforms where not needed (Luming Yu ) [539677 509422]- [fs] private dentry list to avoid dcache_lock contention (Lachlan McIlroy ) [537019 526612]- [scsi] qla2xxx: enable msi-x correctly on qlogic 2xxx series (Marcus Barrow ) [537020 531593]- [apic] fix server c1e spurious lapic timer events (Bhavna Sarathy ) [539681 519422]- [net] netlink: fix typo in initialization (Jiri Pirko ) [528872 527906]- [x86] set cpu_llc_id on AMD CPUs (Bhavna Sarathy ) [539678 513684]- [x86] fix up threshold_bank4 support on AMD Magny-cours (Bhavna Sarathy ) [539678 513684]- [x86] fix up L3 cache information for AMD Magny-cours (Bhavna Sarathy ) [539678 513684]- [x86] amd: fix CPU llc_shared_map information (Bhavna Sarathy ) [539678 513684]- [nfs] v4: fix setting lock on open file with no state (Jeff Layton ) [533114 533115] {CVE-2009-3726}- [misc] futex priority based wakeup (Jon Thomas ) [533858 531552]- [dlm] use GFP_NOFS on all lockspaces (David Teigland ) [533859 530537]- [drm] r128: check for init on all ioctls that require it (Danny Feng ) [529602 529603] {CVE-2009-3620}- [scsi] mpt: errata 28 fix on LSI53C1030 (Tomas Henzl ) [529308 518689]- [x86] add ability to access Nehalem uncore config space (John Villalovos ) [539675 504330]- [net] AF_UNIX: deadlock on connecting to shutdown socket (Jiri Pirko ) [529630 529631] {CVE-2009-3621}- [fs] inotify: remove debug code (Danny Feng ) [533822 499019]- [fs] inotify: fix race (Danny Feng ) [533822 499019]- [audit] dereferencing krule as if it were an audit_watch (Alexander Viro ) [533861 526819]- [mm] fix spinlock performance issue on large systems (John Villalovos ) [539685 526078]- [x86] finish sysdata conversion (Danny Feng ) [537346 519633]- [pci] pciehp: fix PCIe hotplug slot detection (Michal Schmidt ) [530383 521731]- [x86] oprofile: support arch perfmon (John Villalovos ) [539683 523479]- [x86] oprofile: fix K8/core2 on multiple cpus (John Villalovos ) [539683 523479]- [x86] oprofile: utilize perf counter reservation (John Villalovos ) [539683 523479]- [pci] avoid disabling acpi to use non-core PCI devices (Mauro Carvalho Chehab ) [539675 504330]- [misc] support Intel multi-APIC-cluster systems (Prarit Bhargava ) [539676 507333]- [x86] suspend-resume: work on large logical CPU systems (John Villalovos ) [539674 499271]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2009-1670");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2009-1670.html");
script_cve_id("CVE-2009-3612","CVE-2009-3620","CVE-2009-3621","CVE-2009-3726");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.9.1.0.1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.9.1.0.1.el5~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.9.1.0.1.el5PAE~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.9.1.0.1.el5debug~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"ocfs2", rpm:"ocfs2~2.6.18~164.9.1.0.1.el5xen~1.4.4~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.9.1.0.1.el5~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.9.1.0.1.el5PAE~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.9.1.0.1.el5debug~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"oracleasm", rpm:"oracleasm~2.6.18~164.9.1.0.1.el5xen~2.0.5~1.el5", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

