# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0088.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122395");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:18:12 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0088");
script_tag(name: "insight", value: "ELSA-2010-0088 -  kvm security and bug fix update - [kvm-83-105.0.1.el5_4.22]- Add kvm-add-oracle-workaround-for-libvirt-bug.patch[kvm-83-105.el5_4.22]- kvm-CVE-2010-0297-usb-linux.c-fix-buffer-overflow.patch [bz#560769]- Resolves: bz#560769 (CVE-2010-0297 kvm-userspace-rhel5: usb-linux.c: fix buffer overflow [rhel-5.4.z])[kvm-83-105.el5_4.21]- kvm-kernel-KVM-introduce-kvm_read_guest_virt-kvm_write_guest_vi.patch [bz#559093]- kvm-kernel-KVM-remove-the-vmap-usage.patch [bz#559093]- kvm-kernel-KVM-Use-kvm_-read-write-_guest_virt-to-read-and-writ.patch [bz#559093]- kvm-kernel-KVM-fix-memory-access-during-x86-emulation.patch [bz#559093]- kvm-kernel-Check-IOPL-level-during-io-instruction-emulation.patch [bz#560697]- kvm-kernel-Fix-popf-emulation.patch [bz#560697]- kvm-kernel-Check-CPL-level-during-privilege-instruction-emulati.patch [bz#560697]- kvm-kernel-KVM-PIT-control-word-is-write-only.patch [bz#560888]- Resolves: bz#559093 (EMBARGOED CVE-2010-0298 kvm: emulator privilege escalation [rhel-5.4.z])- Resolves: bz#560697 (EMBARGOED CVE-2010-0306 kvm: emulator privilege escalation IOPL/CPL level check [rhel-5.4.z])- Resolves: bz#560888 (CVE-2010-0309 kvm: cat /dev/port in guest cause the host hang [rhel-5.4.z])[kvm-83-105.el5_4.20]- Updated kversion to 2.6.18-164.11.1.el5 to match build root- kvm-qemu-add-routines-for-atomic-16-bit-accesses.patch [bz#561022]- kvm-qemu-virtio-atomic-access-for-index-values.patch [bz#561022]- Resolves: bz#561022 (QEMU terminates without warning with virtio-net and SMP enabled)[kvm-83-105.el5_4.19]- Updated kversion to 2.6.18-164.10.1.el5 to match build root- kvm-Fix-VDI-audio-stop.patch [bz#552519]- Resolves: bz#552519 (KVM : QEMU-Audio attempting to stop unactivated audio device (snd_playback_stop: ASSERT playback_channel->base.active failed).)[kvm-83-105.el5_4.18]- kvm-Fix-a-race-in-the-device-that-cuased-guest-stack-on-.patch [bz#553249]- Resolves: bz#553249 (hypercall device - Vm becomes non responsive on Sysmark benchmark (when more than 7 vm's running simultaneously))[kvm-83-105.el5_4.17]- kvm-kernel-KVM-x86-make-double-triple-fault-promotion-generic-t.patch [bz#552518]- kvm-kernel-KVM-x86-raise-TSS-exception-for-NULL-CS-and-SS-segme.patch [bz#552518]- Resolves: bz#552518 (Rhev-Block driver causes 'unhandled vm exit' with 32bit win2k3r2sp2 Guest VM on restart)- kvm-RHEL-5.X-5.4.Z-Makefile-fix-ksm-dir-has-no-ARCH-pref.patch [bz#552530]- Resolves: bz#552530 (Build tree for RHEL 5.X and RHEL 5.4.z contains build bugs)[kvm-83-105.el5_4.16]- kvm-savevm-add-version_id-to-all-savevm-functions.patch [bz#552529]- kvm-We-need-current-machine-defined-sooner.patch [bz#552529]- kvm-Add-support-for-DeviceVersion-to-machine-type.patch [bz#552529]- kvm-Add-machine-name-alias-support.patch [bz#552529]- kvm-Introduce-rhel5.4.0-machine-type.patch [bz#552529]- kvm-Introduce-rhel-5.4.4-machine-type.patch [bz#552529]- kvm-cpu-for-x86-don-t-save-new-fields-if-version-8.patch [bz#552529]- kvm-RHEL5.4-needs-cpu-at-version-7.patch [bz#552529]- kvm-RHEL-5.4.0-don-t-have-kvmclock.patch [bz#552529]- kvm-make-5.4.0-machine-the-default.patch [bz#552529]- kvm-make-pc-an-alias-of-rhel5.4.0.patch [bz#552529]- Resolves: bz#552529 (kvm: migration: mechanism to make older savevm versions to be emitted on some cases)[kvm-83-105.el5_4.15]- kvm-The-driver-device-pair-does-not-have-a-reset-option-.patch [bz#552528]- kvm-1-The-driver-device-pair-does-not-have-a-reset-option].patch [bz#552528]- Resolves: bz#552528 (Hypercall driver doesn't reset device on power-down)[kvm-83-105.el5_4.14]- Updated kversion to 2.6.18-164.9.1.el5 to match build root- kmod: filter only known non-whitelisted symbols [bz#547293]- Resolves: bz#547293 (kvm kmod package should filter only some specific ksym dependencies)- kvm-kernel-KERNEL-v2-allow-userspace-to-adjust-kvmclock-offset.patch [bz#537028]- kvm-kernel-KVM-MMU-remove-prefault-from-invlpg-handler.patch [bz#548368]- Resolves: bz#537028 (pvclock msr values are not preserved across remote migration)- Resolves: bz#548368 (BSOD BAD_POOL_HEADER STOP 0x19 during boot of Windows Server 2008 R2 installer)- kvm-fix-kvm_arch_save_regs-MSR_COUNT.patch [bz#537028]- kvm-properly-save-kvm-system-time-msr-registers.patch [bz#537028]- kvm-get-and-set-clock-upon-migration.patch [bz#537028]- kvm-slirp-Reassign-same-address-to-same-DHCP-client.patch [bz#546562]- kvm-Fix-race-between-migration-and-cpu-main-loop.patch [bz#546563]- kvm-Make-SMBIOS-pass-MS-SVVP-test.patch [bz#545874]- kvm-fix-rtc-td-hack-on-host-without-high-res-timers.patch [bz#547625]- kvm-qcow2-Fix-grow_refcount_table-error-handling.patch [bz#552159]- Resolves: bz#537028 (pvclock msr values are not preserved across remote migration)- Resolves: bz#545874 (Need to generate SMBIOS table 4 data for windows guests)- Resolves: bz#546562 (Windows XP unattended install doesn't get an IP address after rebooting, if using -net user)- Resolves: bz#546563 (Windows Server 2008 R2 shutdown hangs after restore from migration)- Resolves: bz#547625 (time drift in win2k364 KVM guest)- Resolves: bz#552159 (qcow2: infinite recursion on grow_refcount_table() error handling)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0088");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0088.html");
script_cve_id("CVE-2010-0297","CVE-2010-0298","CVE-2010-0306","CVE-2010-0309");
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
  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~105.0.1.el5_4.22", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~105.0.1.el5_4.22", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~105.0.1.el5_4.22", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~105.0.1.el5_4.22", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

