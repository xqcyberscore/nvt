# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1849.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122019");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:11:47 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-1849");
script_tag(name: "insight", value: "ELSA-2011-1849 -  kernel security and bug fix update - [2.6.32-220.2.1.el6]- [dm] fixing test for NULL pointer testing (Paolo Bonzini) [752379 752380] {CVE-2011-4127}[2.6.32-220.1.1.el6]- [dm] do not forward ioctls from logical volumes to the underlying device (Paolo Bonzini) [752379 752380] {CVE-2011-4127}- [block] fail SCSI passthrough ioctls on partition devices (Paolo Bonzini) [752379 752380] {CVE-2011-4127}- [block] add and use scsi_blk_cmd_ioctl (Paolo Bonzini) [752379 752380] {CVE-2011-4127}- [x86] amd: Fix align_va_addr kernel parameter (Frank Arnold) [758028 753237]- [md] RAID1: Do not call md_raid1_unplug_device while holding spinlock (Jonathan E Brassow) [755545 752528]- [pci] intel-iommu: Default to non-coherent for domains unattached to iommus (Don Dutile) [757671 746484]- [x86] initialize min_delta_ns in one_hpet_msi_clockevent() (Prarit Bhargava) [756426 728315]- [x86] Update hpet_next_event() (Prarit Bhargava) [756426 728315]- [kernel] sched: Use resched IPI to kick off the nohz idle balance (Vivek Goyal) [750459 717179]- [drm] i915: enable ring freq scaling, RC6 and graphics turbo on Ivy Bridge (Prarit Bhargava) [758513 752163]- [drm] i915: load a ring frequency scaling table (Prarit Bhargava) [758513 752163]- [x86] cpufreq: expose a cpufreq_quick_get_max routine (Prarit Bhargava) [758513 752163]- [sched] Cleanup/optimize clock updates (Larry Woodman) [751403 750237]- [sched] fix skip_clock_update optimization (Larry Woodman) [751403 750237]- [block] virtio-blk: Use ida to allocate disk index (Michael S. Tsirkin) [756427 692767]- [virt] virtio_blk: Replace cryptic number with the macro (Michael S. Tsirkin) [756427 692767]- [kernel] ida: simplified functions for id allocation (Michael S. Tsirkin) [756427 692767]- [virt] revert virtio-blk: Use ida to allocate disk index (Aristeu Rozanski) [756427 692767]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1849");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1849.html");
script_cve_id("CVE-2011-4127");
script_tag(name:"cvss_base", value:"4.6");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
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
if(release == "OracleLinux6")
{
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.2.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

