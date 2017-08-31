# OpenVAS Vulnerability Test 
# Description: Oracle Linux Local Check 
# $Id: ELSA-2010-0126.nasl 6555 2017-07-06 11:54:09Z cfischer $
 
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
script_oid("1.3.6.1.4.1.25623.1.0.122390");
script_version("$Revision: 6555 $");
script_tag(name:"creation_date", value:"2015-10-06 14:18:04 +0300 (Tue, 06 Oct 2015)");
script_tag(name:"last_modification", value:"$Date: 2017-07-06 13:54:09 +0200 (Thu, 06 Jul 2017) $");
script_name("Oracle Linux Local Check: ELSA-2010-0126");
script_tag(name: "insight", value: "ELSA-2010-0126 -  kvm security and bug fix update - [kvm-83-105.0.1.el5_4.27]- Add kvm-add-oracle-workaround-for-libvirt-bug.patch[kvm-83-105.el5_4.27]- kvm-kernel-KVM-VMX-Check-cpl-before-emulating-debug-register-ac.patch [bz#563516]- Resolves: bz#563516 (KVM: Check cpl before emulating debug register access [rhel-5.4.z])[kvm-83-105.el5_4.26]- kvm-kernel-KVM-Don-t-check-access-permission-when-loading-segme.patch [bz#563464]- kvm-kernel-KVM-Disable-move-to-segment-registers-and-jump-far-i.patch [bz#563464]- Resolves: bz#563464 (EMBARGOED CVE-2010-0419 kvm: emulator privilege escalation segment selector check [rhel-5.4.z])[kvm-83-105.el5_4.25]- kvm-virtio-blk-Fix-reads-turned-into-writes-after-read-e.patch [bz#562776]- kvm-virtio-blk-Handle-bdrv_aio_read-write-NULL-return.patch [bz#562776]- Resolves: bz#562776 (Guest image corruption after RHEV-H update to 5.4-2.1.3.el5_4rhev2_1)[kvm-83-105.el5_4.24]- Apply bz#561022 patches again (undo the reverts from kvm-83-105.el5_4.23)- kvm-qemu-add-routines-for-atomic-16-bit-accesses-take-2.patch [bz#561022]- kvm-qemu-virtio-atomic-access-for-index-values-take-2.patch [bz#561022]- Resolves: bz#561022 (QEMU terminates without warning with virtio-net and SMP enabled)[kvm-83-105.el5_4.23]- Revert bz#561022 patches by now, until they get better testing- kvm-Revert-qemu-virtio-atomic-access-for-index-values.patch [bz#561022]- kvm-Revert-qemu-add-routines-for-atomic-16-bit-accesses.patch [bz#561022]- Related: bz#561022 (QEMU terminates without warning with virtio-net and SMP enabled)"); 
script_tag(name : "solution", value : "update software");
script_tag(name : "solution_type", value : "VendorFix");
script_tag(name : "summary", value : "Oracle Linux Local Security Checks ELSA-2010-0126");
script_xref(name : "URL" , value : "http://linux.oracle.com/errata/ELSA-2010-0126.html");
script_cve_id("CVE-2009-3722","CVE-2010-0419");
script_tag(name:"cvss_base", value:"7.1");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
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
  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~105.0.1.el5_4.27", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~105.0.1.el5_4.27", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~105.0.1.el5_4.27", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }
  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~105.0.1.el5_4.27", rls:"OracleLinux5")) != NULL) {
    security_message(data:res);
    exit(0);  
  }

}
if (__pkg_match) exit(99); #Not vulnerable
  exit(0);

