# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2011-1189.nasl 6556 2017-07-06 11:54:54Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122103");
script_version("$Revision: 6556 $");
script_tag(name:"creation_date", value:"2015-10-06 14:13:08 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:54 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2011-1189");
script_tag(name: "insight", value: "ELSA-2011-1189 -  kernel security, bug fix, and enhancement update - [2.6.32-131.12.1.el6]- [netdrv] be2net: clear intr bit in be_probe() (Ivan Vecera) [726308 722596][2.6.32-131.11.1.el6]- [mm] hold the page lock until after set_page_stable_node (Andrea Arcangeli) [726095 683658]- [netdrv] be2net: remove certain cmd failure logging (Ivan Vecera) [725329 719304]- [net] nl80211: missing check for valid SSID size in scan operation (Stanislaw Gruszka) [718157 718158] {CVE-2011-2517}- [net] bluetooth: l2cap and rfcomm: fix 1 byte infoleak to userspace. (Thomas Graf) [703022 703023] {CVE-2011-2492}- [net] inet_diag: fix validation of user data in inet_diag_bc_audit() (Thomas Graf) [714540 714541] {CVE-2011-2213}- [fs] proc: restrict access to /proc/PID/io (Oleg Nesterov) [716829 716830] {CVE-2011-2495}- [fs] validate size of EFI GUID partition entries (Anton Arapov) [703029 703030] {CVE-2011-1776}- [fs] ext4: Fix max file size and logical block counting of extent format file (Lukas Czerner) [722568 722569] {CVE-2011-2695}- [virt] kvm: Disable device assignment without interrupt remapping (Alex Williamson) [716306 711504] {CVE-2011-1898}- [virt] iommu-api: Extension to check for interrupt remapping (Alex Williamson) [716306 711504] {CVE-2011-1898}- [netdrv] r8169: fix Rx checksum offloading bugs (Ivan Vecera) [723807 635596]- [netdrv] be2net: changes for BE3 native mode support (Ivan Vecera) [723820 695231][2.6.32-131.10.1.el6]- [virt] ksm: fix race between ksmd and exiting task (Andrea Arcangeli) [710340 710341] {CVE-2011-2183}- [kernel] proc: signedness issue in next_pidmap() (Jerome Marchand) [697824 697825] {CVE-2011-1593}- [net] bluetooth: Prevent buffer overflow in l2cap config request (Jiri Pirko) [716809 716810] {CVE-2011-2497}- [fs] NLM: Don't hang forever on NLM unlock requests (Jeff Layton) [709548 709549] {CVE-2011-2491}- [fs] NFS: Fix NFSv3 exclusive open semantics (Jeff Layton) [719925 694210]- [fs] GFS2: Incorrect inode state during deallocation (Steven Whitehouse) [714982 712139]- [virt] KVM: Fix register corruption in pvclock_scale_delta (Avi Kivity) [719910 712102]- [netdrv] ehea: Fix memory hotplug oops (Steve Best) [720914 702036]- [net] Fix memory leak/corruption on VLAN GRO_DROP (Herbert Xu) [695175 695176] {CVE-2011-1576}- [md] Fix resync hang after surprise removal (James Paradis) [719928 707268]- GFS2: make sure fallocate bytes is a multiple of blksize (Benjamin Marzinski) [720863 695763] {CVE-2011-2689}- [kernel] Prevent rt_sigqueueinfo and rt_tgsigqueueinfo from spoofing the signal code (Oleg Nesterov) [715521 690033] {CVE-2011-1182}- [redhat] config: enable parallel port printer support (Aristeu Rozanski) [713827 635968][2.6.32-131.9.1.el6]- [scsi] cciss: Annotate cciss_kdump_soft_reset and cciss_sent_reset as __devinit (Tomas Henzl) [715397 698268]- [scsi] cciss: Don't wait forever for soft reset to complete, give up after awhile (Tomas Henzl) [715397 698268]- [scsi] cciss: use cmd_alloc not cmd_special_alloc for the kdump soft reset command (Tomas Henzl) [715397 698268]- [scsi] cciss: do not use bit 2 doorbell reset (Tomas Henzl) [715397 698268]- [scsi] cciss: do not attempt PCI power management reset method if we know it won't work (Tomas Henzl) [715397 698268]- [scsi] cciss: increase timeouts for post-reset no-ops (Tomas Henzl) [715397 698268]- [scsi] cciss: remove superfluous sleeps around reset code (Tomas Henzl) [715397 698268]- [scsi] cciss: do soft reset if hard reset is broken (Tomas Henzl) [715397 698268]- [scsi] cciss: clarify messages around reset behavior (Tomas Henzl) [715397 698268]- [scsi] cciss: increase time to wait for board reset to start (Tomas Henzl) [715397 698268]- [scsi] cciss: factor out irq_request code (Tomas Henzl) [715397 698268]- [scsi] cciss: factor out scatterlist allocation functions (Tomas Henzl) [715397 698268]- [scsi] cciss: factor out command pool allocation functions (Tomas Henzl) [715397 698268]- [scsi] cciss: use new doorbell-bit-5 reset method (Tomas Henzl) [715397 698268]- [scsi] cciss: wait longer for no-op to complete after resetting controller (Tomas Henzl) [715397 698268]- [scsi] cciss: do a better job of detecting controller reset failure (Tomas Henzl) [715397 698268]- [scsi] hpsa: do not attempt PCI PM reset if we know it will not work (Tomas Henzl) [715397 698268]- [scsi] hpsa: remove superfluous sleeps around reset code (Tomas Henzl) [715397 698268]- [scsi] hpsa: do soft reset if hard reset is broken (Tomas Henzl) [715397 698268]- [scsi] hpsa: clarify messages around reset behavior (Tomas Henzl) [715397 698268]- [scsi] hpsa: factor out irq request code (Tomas Henzl) [715397 698268]- [scsi] hpsa: factor out cmd_pool allocation functions (Tomas Henzl) [715397 698268]- [scsi] hpsa: do not use bit 2 doorbell reset, it causes NMIs (Tomas Henzl) [715397 698268]- [scsi] hpsa: wait longer for no-op to complete after resetting controller (Tomas Henzl) [715397 698268]- [scsi] hpsa: use new doorbell-bit-5 reset method (Tomas Henzl) [715397 698268]- [scsi] hpsa: adjust timing of post-reset sleeps (Tomas Henzl) [715397 698268]- [scsi] hpsa: do a better job of detecting controller reset failure (Tomas Henzl) [715397 698268][2.6.32-131.8.1.el6]- [fs] GFS2: force a log flush when invalidating the rindex glock (Benjamin Marzinski) [717018 702263][2.6.32-131.7.1.el6]- [virt] xen: bump memory limit for x86_64 domU PV guest to 128Gb (Igor Mammedov) [716539 669739]"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2011-1189");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2011-1189.html");
script_cve_id("CVE-2011-1182","CVE-2011-1576","CVE-2011-1593","CVE-2011-1776","CVE-2011-1898","CVE-2011-2183","CVE-2011-2213","CVE-2011-2491","CVE-2011-2492","CVE-2011-2495","CVE-2011-2497","CVE-2011-2517","CVE-2011-2689","CVE-2011-2695");
script_tag(name:"cvss_base", value:"8.3");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~131.12.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~131.12.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~131.12.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~131.12.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~131.12.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~131.12.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~131.12.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~131.12.1.el6", rls:"OracleLinux6")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

