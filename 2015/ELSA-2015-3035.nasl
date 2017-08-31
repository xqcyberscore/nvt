# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2015-3035.nasl 6560 2017-07-06 11:58:38Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123113");
script_version("$Revision: 6560 $");
script_tag(name:"creation_date", value:"2015-10-06 09:48:03 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:58:38 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2015-3035");
script_tag(name: "insight", value: "ELSA-2015-3035 - Unbreakable Enterprise kernel security and bugfix update - kernel-uek[3.8.13-68.2.2]- crypto: aesni - fix memory usage in GCM decryption (Stephan Mueller) [Orabug: 21077385] {CVE-2015-3331}[3.8.13-68.2.1]- xen/pciback: Don't disable PCI_COMMAND on PCI device reset. (Konrad Rzeszutek Wilk) [Orabug: 20807438] {CVE-2015-2150}- xen-blkfront: fix accounting of reqs when migrating (Roger Pau Monne) [Orabug: 20860817] - Doc/cpu-hotplug: Specify race-free way to register CPU hotplug callbacks (Srivatsa S. Bhat) [Orabug: 20917697] - net/iucv/iucv.c: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - net/core/flow.c: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - mm, vmstat: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - profile: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - trace, ring-buffer: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - hwmon, via-cputemp: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - hwmon, coretemp: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - octeon, watchdog: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - oprofile, nmi-timer: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - intel-idle: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - drivers/base/topology.c: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - acpi-cpufreq: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - scsi, fcoe: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - scsi, bnx2fc: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - scsi, bnx2i: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - arm64, debug-monitors: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - arm64, hw_breakpoint.c: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, kvm: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, oprofile, nmi: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, pci, amd-bus: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, hpet: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, intel, cacheinfo: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, amd, ibs: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, therm_throt.c: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, mce: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, intel, uncore: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, vsyscall: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, cpuid: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - x86, msr: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - powerpc, sysfs: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - sparc, sysfs: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - s390, smp: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - s390, cacheinfo: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - arm, hw-breakpoint: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - ia64, err-inject: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - ia64, topology: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - ia64, palinfo: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - CPU hotplug, perf: Fix CPU hotplug callback registration (Srivatsa S. Bhat) [Orabug: 20917697] - CPU hotplug: Provide lockless versions of callback registration functions (Srivatsa S. Bhat) [Orabug: 20917697] - isofs: Fix unchecked printing of ER records (Jan Kara) [Orabug: 20930551] {CVE-2014-9584}- KEYS: close race between key lookup and freeing (Sasha Levin) [Orabug: 20930548] {CVE-2014-9529} {CVE-2014-9529}- mm: memcg: do not allow task about to OOM kill to bypass the limit (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}- mm: memcg: do not declare OOM from __GFP_NOFAIL allocations (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}- fs: buffer: move allocation failure loop into the allocator (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}- mm: memcg: handle non-error OOM situations more gracefully (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}- mm: memcg: do not trap chargers with full callstack on OOM (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}- mm: memcg: rework and document OOM waiting and wakeup (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}- mm: memcg: enable memcg OOM killer only for user faults (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}- x86: finish user fault error path with fatal signal (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}- arch: mm: pass userspace fault flag to generic fault handler (Johannes Weiner) [Orabug: 20930539] {CVE-2014-8171}- selinux: Permit bounded transitions under NO_NEW_PRIVS or NOSUID. (Stephen Smalley) [Orabug: 20930501] {CVE-2014-3215}- IB/core: Prevent integer overflow in ib_umem_get address arithmetic (Shachar Raindel) [Orabug: 20799875] {CVE-2014-8159} {CVE-2014-8159}"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2015-3035");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2015-3035.html");
script_cve_id("CVE-2015-2150","CVE-2015-3331");
script_tag(name:"cvss_base", value:"9.3");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"dtrace-modules", rpm:"dtrace-modules~3.8.13~68.2.2.el7uek~0.4.3~4.el7", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.2.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.2.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.2.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.2.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.2.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.2.2.el7uek", rls:"OracleLinux7")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"dtrace-modules", rpm:"dtrace-modules~3.8.13~68.2.2.el6uek~0.4.3~4.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek", rpm:"kernel-uek~3.8.13~68.2.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug", rpm:"kernel-uek-debug~3.8.13~68.2.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-debug-devel", rpm:"kernel-uek-debug-devel~3.8.13~68.2.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-devel", rpm:"kernel-uek-devel~3.8.13~68.2.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-doc", rpm:"kernel-uek-doc~3.8.13~68.2.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-uek-firmware", rpm:"kernel-uek-firmware~3.8.13~68.2.2.el6uek", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

