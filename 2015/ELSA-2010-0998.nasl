# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0998.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122286");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:16:00 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0998");
script_tag(name: "insight", value: "ELSA-2010-0998 -  kvm security and bug fix update - [kvm-83-164.0.1.el5_5.30]- Added kvm-add-oracle-workaround-for-libvirt-bug.patch to replace RHEL with OEL- Added kvm-Introduce-oel-machine-type.patch so that OEL is a recognized VM[kvm-83-164.el5_5.30]- Revert the bz#661397 patches as they are not enough - kvm-kernel-Revert-KVM-VMX-Return-0-from-a-failed-VMREAD.patch [bz#661397] - kvm-kernel-Revert-KVM-Don-t-spin-on-virt-instruction-faults-dur.patch [bz#661397]- Related: bz#661397 (reboot(RB_AUTOBOOT) fails if kvm instance is running)- kvm-kernel-KVM-fix-AMD-initial-TSC-offset-problems-additional-f.patch [bz#656984]- Resolves: bz#656984 (TSC offset of virtual machines is not initialized correctly by 'kvm_amd' kernel module.)[kvm-83-164.el5_5.29]- kvm-kernel-KVM-Don-t-spin-on-virt-instruction-faults-during-reb.patch [bz#661397]- kvm-kernel-KVM-VMX-Return-0-from-a-failed-VMREAD.patch [bz#661397]- Resolves: bz#661397 (reboot(RB_AUTOBOOT) fails if kvm instance is running)[kvm-83-164.el5_5.28]- kvm-implement-dummy-PnP-support.patch [bz#659850]- kvm-load-registers-after-restoring-pvclock-msrs.patch [bz#660239]- Resolves: bz#659850 (If VM boot seq. is set up as nc (PXE then disk) the VM is always stuck on trying to PXE boot)- Resolves: bz#660239 (clock drift when migrating a guest between mis-matched CPU clock speed)[kvm-83-164.el5_5.27]- kvm-kernel-KVM-fix-AMD-initial-TSC-offset-problems.patch [bz#656984]- Resolves: bz#656984 (TSC offset of virtual machines is not initialized correctly by 'kvm_amd' kernel module.)[kvm-83-164.el5_5.26]- Updated kversion to 2.6.18-194.26.1.el5 to match build root- kvm-kernel-KVM-x86-fix-information-leak-to-userland.patch [bz#649832]- Resolves: bz#649832 (CVE-2010-3881 kvm: arch/x86/kvm/x86.c: reading uninitialized stack memory [5.5.z])- CVE: CVE-2010-3881"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0998");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0998.html");
script_cve_id("CVE-2010-3881");
script_tag(name:"cvss_base", value:"1.9");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
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
  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~164.0.1.el5_5.30", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~164.0.1.el5_5.30", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~164.0.1.el5_5.30", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~164.0.1.el5_5.30", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

