# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2013-0727.nasl 6558 2017-07-06 11:56:55Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123647");
script_version("$Revision: 6558 $");
script_tag(name:"creation_date", value:"2015-10-06 14:06:45 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:56:55 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2013-0727");
script_tag(name: "insight", value: "ELSA-2013-0727 -  kvm security update - [kvm-83-262.0.1.el5_9.3]- Added kvm-add-oracle-workaround-for-libvirt-bug.patch- Added kvm-Introduce-oel-machine-type.patch[kvm-83-262.el5_3]- kvm-kernel-kvm-accept-unaligned-MSR_KVM_SYSTEM_TIME-writes.patch [bz#947363]- Resolves: bz#947363 (RHEL.5.8.32 guest hang when installing)[kvm-83-262.el5_2]- kvm-kernel-KVM-Fix-for-buffer-overflow-in-handling-of-MSR_KVM_S.patch [bz#917018]- kvm-kernel-KVM-Convert-MSR_KVM_SYSTEM_TIME-to-use-kvm_write_gue.patch [bz#917022]- kvm-kernel-KVM-Fix-bounds-checking-in-ioapic-indirect-register-.patch [bz#917028]- kvm-kernel-do-not-GP-on-unaligned-MSR_KVM_SYSTEM_TIME-write.patch [bz#bz917019]- Resolves: bz#917018 (CVE-2013-1796 kernel: kvm: buffer overflow in handling of MSR_KVM_SYSTEM_TIME [rhel-5.9.z])- Resolves: bz#917022 (CVE-2013-1797 kernel: kvm: after free issue with the handling of MSR_KVM_SYSTEM_TIME [rhel-5.9.z])- Resolves: bz#917028 (CVE-2013-1798 kernel: kvm: out-of-bounds access in ioapic indirect register reads [rhel-5.9.z])"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2013-0727");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2013-0727.html");
script_cve_id("CVE-2013-1796","CVE-2013-1797","CVE-2013-1798");
script_tag(name:"cvss_base", value:"6.8");
script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
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
  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~262.0.1.el5_9.3", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~262.0.1.el5_9.3", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~262.0.1.el5_9.3", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~262.0.1.el5_9.3", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~262.0.1.el5_9.3", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

