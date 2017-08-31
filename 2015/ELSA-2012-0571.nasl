# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0571.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123922");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:10:19 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0571");
script_tag(name: "insight", value: "ELSA-2012-0571 -  kernel security and bug fix update - [2.6.32-220.17.1.el6]- [scsi] fcoe: Do not switch context in vport_delete callback (Neil Horman) [809388 806119][2.6.32-220.16.1.el6]- Revert: [x86] Ivy Bridge kernel rdrand support (Jay Fenlason) [800268 696442][2.6.32-220.15.1.el6]- [net] SUNRPC: We must not use list_for_each_entry_safe() in rpc_wake_up() (Steve Dickson) [811299 809928]- [char] ipmi: Increase KCS timeouts (Matthew Garrett) [806906 803378]- [kernel] sched: Fix ancient race in do_exit() (Frantisek Hrbata) [805457 784758]- [scsi] sd: Unmap discard alignment needs to be converted to bytes (Mike Snitzer) [810322 805519]- [scsi] sd: Fix VPD buffer allocations (Mike Snitzer) [810322 805519]- [x86] Ivy Bridge kernel rdrand support (Jay Fenlason) [800268 696442]- [scsi] fix system lock up from scsi error flood (Frantisek Hrbata) [809378 800555]- [sound] ALSA: pcm midlevel code - add time check for (Jaroslav Kysela) [801329 798984]- [pci] Add pcie_hp=nomsi to disable MSI/MSI-X for pciehp driver (hiro muneda) [807426 728852]- [sound] ALSA: enable OSS emulation layer for PCM and mixer (Jaroslav Kysela) [812960 657291]- [scsi] qla4xxx: Fixed BFS with sendtargets as boot index (Chad Dupuis) [803881 722297]- [fs] nfs: Additional readdir cookie loop information (Steve Dickson) [811135 770250]- [fs] NFS: Fix spurious readdir cookie loop messages (Steve Dickson) [811135 770250]- [x86] powernow-k8: Fix indexing issue (Frank Arnold) [809391 781566]- [x86] powernow-k8: Avoid Pstate MSR accesses on systems supporting CPB (Frank Arnold) [809391 781566]- [redhat] spec: Add python-perf-debuginfo subpackage (Josh Boyer) [806859 806859][2.6.32-220.14.1.el6]- [net] fix vlan gro path (Jiri Pirko) [810454 720611]- [virt] VMX: vmx_set_cr0 expects kvm->srcu locked (Marcelo Tosatti) [808206 807507] {CVE-2012-1601}- [virt] KVM: Ensure all vcpus are consistent with in-kernel irqchip settings (Marcelo Tosatti) [808206 807507] {CVE-2012-1601}- [scsi] fcoe: Move destroy_work to a private work queue (Neil Horman) [809388 806119]- [fs] jbd2: clear BH_Delay & BH_Unwritten in journal_unmap_buffer (Eric Sandeen) [749727 748713] {CVE-2011-4086}- [net] af_iucv: offer new getsockopt SO_MSGSIZE (Hendrik Brueckner) [804547 786997]- [net] af_iucv: performance improvements for new HS transport (Hendrik Brueckner) [804548 786996]- [s390x] af_iucv: remove IUCV-pathes completely (Hendrik Brueckner) [807158 786960]- [x86] iommu/amd: Fix wrong shift direction (Don Dutile) [809376 781531]- [x86] iommu/amd: Don't use MSI address range for DMA addresses (Don Dutile) [809374 781524]- [fs] NFSv4: Further reduce the footprint of the idmapper (Steve Dickson) [802852 730045]- [fs] NFSv4: Reduce the footprint of the idmapper (Steve Dickson) [802852 730045]- [scsi] fcoe: Make fcoe_transport_destroy a synchronous operation (Neil Horman) [809372 771251]- [net] ipv4: Constrain UFO fragment sizes to multiples of 8 bytes (Jiri Benc) [809104 797731]- [net] ipv4: Don't use ufo handling on later transformed packets (Jiri Benc) [809104 797731]- [net] udp: Add UFO to NETIF_F_GSO_SOFTWARE (Jiri Benc) [809104 797731]- [fs] nfs: Try using machine credentials for RENEW calls (Sachin Prabhu) [806205 795441]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0571");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0571.html");
script_cve_id("CVE-2011-4086","CVE-2012-1601");
script_tag(name:"cvss_base", value:"4.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.17.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

