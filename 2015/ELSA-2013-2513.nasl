# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-2513.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123645");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:43 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-2513");
script_tag(name: "insight", value: "ELSA-2013-2513 - Unbreakable Enterprise kernel security and bugfix update - [2.6.39-400.21.1]- SPEC: v2.6.39-400.21.1 (Maxim Uvarov)- xen/mmu: On early bootup, flush the TLB when changing RO->RW bits Xen provided pagetables. (Konrad Rzeszutek Wilk)[2.6.39-400.20.1]- SPEC: v2.6.39-400.20.1 (Maxim Uvarov)- PCI: Set device power state to PCI_D0 for device without native PM support (Ajaykumar Hotchandani) [Orabug: 16482495]- sched: Fix cgroup movement of waking process (Daisuke Nishimura) [Orabug: 13740515]- sched: Fix cgroup movement of newly created process (Daisuke Nishimura) [Orabug: 13740515]- sched: Fix cgroup movement of forking process (Daisuke Nishimura) [Orabug: 13740515][2.6.39-400.19.1]- IB/core: Allow device-specific per-port sysfs files (Ralph Campbell)- RDMA/cma: Pass QP type into rdma_create_id() (Sean Hefty)- IB: Rename RAW_ETY to RAW_ETHERTYPE (Aleksey Senin)- IB: Warning Resolution. (Ajaykumar Hotchandani)- mlx4_core: fix FMR flags in free MTT range (Saeed Mahameed)- mlx4_core/ib: sriov fmr bug fixes (Saeed Mahameed)- mlx4_core: Change bitmap allocator to work in round-robin fashion (Saeed Mahameed)- mlx4_vnic: move host admin vnics to closed state when closing the vnic. (Saeed Mahameed)- mlx4_ib: make sure to flush clean_wq while closing sriov device (Saeed Mahameed)- ib_sdp: fix deadlock when sdp_cma_handler is called while socket is being closed (Saeed Mahameed)- ib_sdp: add unhandled events to rdma_cm_event_str (Saeed Mahameed)- mlx4_core: use dev->sriov instead of hardcoed 127 vfs when initializing FMR MPT tables (Saeed Mahameed)- mlx4_vnic: print vnic keep alive info in mlx4_vnic_info (Saeed Mahameed)- rds: Congestion flag does not get cleared causing the connection to hang (Bang Nguyen) [Orabug: 16424692]- dm table: set flush capability based on underlying devices (Mike Snitzer) [Orabug: 16392584]- wake_up_process() should be never used to wakeup a TASK_STOPPED/TRACED task (Oleg Nesterov) [Orabug: 16405869] {CVE-2013-0871}- ptrace: ensure arch_ptrace/ptrace_request can never race with SIGKILL (Oleg Nesterov) [Orabug: 16405869] {CVE-2013-0871}- ptrace: introduce signal_wake_up_state() and ptrace_signal_wake_up() (Oleg Nesterov) [Orabug: 16405869] {CVE-2013-0871}- drm/i915: bounds check execbuffer relocation count (Kees Cook) [Orabug: 16482650] {CVE-2013-0913}- NLS: improve UTF8 -> UTF16 string conversion routine (Alan Stern) [Orabug: 16425571] {CVE-2013-1773}- ipmi: make kcs timeout parameters as module options (Pavel Bures) [Orabug: 16470881]- drm/i915/lvds: ditch ->prepare special case (Daniel Vetter) [Orabug: 14394113]- drm/i915: Leave LVDS registers unlocked (Keith Packard) [Orabug: 14394113]- drm/i915: dont clobber the pipe param in sanitize_modesetting (Daniel Vetter) [Orabug: 14394113]- drm/i915: Sanitize BIOS debugging bits from PIPECONF (Chris Wilson) [Orabug: 14394113][2.6.39-400.18.1]- SPEC: fix doc build (Guru Anbalagane)- floppy: Fix a crash during rmmod (Vivek Goyal) [Orabug: 16040504]- x86: ignore changes to paravirt_lazy_mode while in an interrupt context (Chuck Anderson) [Orabug: 16417326]- x86/msr: Add capabilities check (Alan Cox) [Orabug: 16405007] {CVE-2013-0268}- spec: unique debuginfo (Maxim Uvarov) [Orabug: 16245366]- xfs: Use preallocation for inodes with extsz hints (Dave Chinner) [Orabug: 16307993]- Add SIOCRDSGETTOS to get the current TOS for the socket (bang.nguyen) [Orabug: 16397197]- Changes to connect/TOS interface (bang.nguyen) [Orabug: 16397197]- floppy: Cleanup disk->queue before caling put_disk() if add_disk() was never called (Vivek Goyal) [Orabug: 16040504]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-2513");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-2513.html");
script_cve_id("CVE-2013-0871","CVE-2013-0913","CVE-2013-1773");
script_tag(name:"cvss_base", value:"7.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.21.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.21.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.21.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.21.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.21.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.21.1.el5uek", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~2.6.39~400.21.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~2.6.39~400.21.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~2.6.39~400.21.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~2.6.39~400.21.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~2.6.39~400.21.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~2.6.39~400.21.1.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

