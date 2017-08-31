# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2014-0163.nasl 6559 2017-07-06 11:57:32Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123467");
script_version("$Revision: 6559 $");
script_tag(name:"creation_date", value:"2015-10-06 14:04:12 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:57:32 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2014-0163");
script_tag(name: "insight", value: "ELSA-2014-0163 -  kvm security update - [kvm-83-266.0.1.el5_10.1]- Added kvm-add-oracle-workaround-for-libvirt-bug.patch- Added kvm-Introduce-oel-machine-type.patch[kvm-83-266_10.1.el5]- KVM: x86: prevent cross page vapic_addr access (CVE-2013-6368) [bz#1032219]- KVM: x86: Fix potential divide by 0 in lapic (CVE-2013-6367) [bz#1032216]- Resolves: bz#1032219 (CVE-2013-6368 kvm: cross page vapic_addr access [rhel-5.10])- Resolves: bz#1032216 CVE-2013-6367 kvm: division by zero in apic_get_tmcct() [rhel-5.10.z][kvm-83-266.el5]- Updated kversion to 2.6.18-348.4.1.el5- kvm-fix-l1_map-buffer-overflow.patch [bz#956511]- Resolves: bz#956511 (qemu-kvm segfault in tb_invalidate_phys_page_range())[kvm-83-265.el5]- kvm-kernel-kvm-accept-unaligned-MSR_KVM_SYSTEM_TIME-writes.patch [bz#924597]- Resolves: bz#924597 (RHEL.5.8.32 guest hang when installing)[kvm-83-264.el5]- kvm-kernel-KVM-Fix-for-buffer-overflow-in-handling-of-MSR_KVM_S.patch [bz#917019]- kvm-kernel-KVM-Convert-MSR_KVM_SYSTEM_TIME-to-use-kvm_write_gue.patch [bz#917023]- kvm-kernel-KVM-Fix-bounds-checking-in-ioapic-indirect-register-.patch [bz#917029]- kvm-kernel-do-not-GP-on-unaligned-MSR_KVM_SYSTEM_TIME-write.patch [bz#bz917019]- Resolves: bz#917019 (CVE-2013-1796 kernel: kvm: buffer overflow in handling of MSR_KVM_SYSTEM_TIME [rhel-5.10])- Resolves: bz#917023 (CVE-2013-1797 kernel: kvm: after free issue with the handling of MSR_KVM_SYSTEM_TIME [rhel-5.10])- Resolves: bz#917029 (CVE-2013-1798 kernel: kvm: out-of-bounds access in ioapic indirect register reads [rhel-5.10])[kvm-83-263.el5]- kvm-e1000-Discard-packets-that-are-too-long-if-SBP-and-L.patch [bz#910840]- kvm-e1000-Discard-oversized-packets-based-on-SBP-LPE.patch [bz#910840]- Resolves: bz#910840 (CVE-2012-6075 qemu (e1000 device driver): Buffer overflow when processing large packets when SBP and LPE flags are disabled [rhel-5.10])"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2014-0163");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2014-0163.html");
script_cve_id("CVE-2013-6367","CVE-2013-6368");
script_tag(name:"cvss_base", value:"6.2");
script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~266.0.1.el5_10.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~266.0.1.el5_10.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~266.0.1.el5_10.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~266.0.1.el5_10.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~266.0.1.el5_10.1", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

