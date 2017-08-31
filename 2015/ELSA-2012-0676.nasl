# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2012-0676.nasl 6557 2017-07-06 11:55:33Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.123916");
script_version("$Revision: 6557 $");
script_tag(name:"creation_date", value:"2015-10-06 14:10:15 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:55:33 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2012-0676");
script_tag(name: "insight", value: "ELSA-2012-0676 -  kvm security and bug fix update - [kvm-83-249.0.1.el5_8.4]- Added kvm-add-oracle-workaround-for-libvirt-bug.patch- Added kvm-Introduce-oel-machine-type.patch[kvm-83-249.el5_8.4]- kvm-kernel-KVM-unmap-pages-from-the-iommu-when-slots-are-remove.patch [bz#814151]- CVE: CVE-2012-2121- Resolves: bz#814151 (CVE-2012-2121 kvm: device assignment page leak [rhel-5.8])[kvm-83-249.el5_8.3]- kvm-fix-l1_map-buffer-overflow.patch [bz#816207]- Resolves: bz#816207 (qemu-kvm segfault in tb_invalidate_phys_page_range())[kvm-83-249.el5_8.2]- kvm-kernel-KVM-Ensure-all-vcpus-are-consistent-with-in-kernel-i.patch [bz#808205]- Resolves: bz#808205 (CVE-2012-1601 kernel: kvm: irqchip_in_kernel() and vcpu->arch.apic inconsistency [rhel-5.8.z])[kvm-83-249.el5_8.1]- kvm-posix-aio-compat-fix-thread-accounting-leak.patch [bz#802429]- Resolves: bz#802429 ([RHEL5.8 Snapshot2]RHEL5.8 KVMGuest hung during Guest OS booting up)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2012-0676");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2012-0676.html");
script_cve_id("CVE-2012-1601","CVE-2012-2121");
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
if(release == "OracleLinux5")
{
  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~249.0.1.el5_8.4", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~249.0.1.el5_8.4", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~249.0.1.el5_8.4", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~249.0.1.el5_8.4", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~249.0.1.el5_8.4", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

